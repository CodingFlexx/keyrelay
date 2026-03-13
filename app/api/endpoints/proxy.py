import logging
from typing import Any, Dict

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from app.api.dependencies import verify_proxy_access
from app.core.config import HOP_BY_HOP_HEADERS, SERVICE_CONFIGS, TARGETS
from app.core.security import get_auth_header, get_target_url, is_service_allowed
from app.db.database import get_api_key, get_service_metadata, log_request

logger = logging.getLogger(__name__)

router = APIRouter()


async def _close_upstream(response: httpx.Response, client: httpx.AsyncClient) -> None:
    await response.aclose()
    await client.aclose()


async def proxy_request(
    request: Request,
    service: str,
    path: str,
    user: Dict[str, Any],
) -> StreamingResponse:
    if service not in TARGETS:
        log_request(
            service=service,
            endpoint=f"/{path}",
            client_ip=request.client.host if request.client else "unknown",
            success=False,
            request_method=request.method,
            response_status=404,
            error_message="Unknown service",
            user_agent=request.headers.get("user-agent"),
        )
        raise HTTPException(status_code=404, detail=f"Unknown service: {service}")

    if not is_service_allowed(user, service):
        log_request(
            service=service,
            endpoint=f"/{path}",
            client_ip=request.client.host if request.client else "unknown",
            success=False,
            request_method=request.method,
            response_status=403,
            error_message=f"Service scope denied for user {user.get('username', 'unknown')}",
            user_agent=request.headers.get("user-agent"),
        )
        raise HTTPException(status_code=403, detail=f"Access denied for service: {service}")

    metadata = get_service_metadata(service)
    api_key = get_api_key(service)
    if not api_key:
        log_request(
            service=service,
            endpoint=f"/{path}",
            client_ip=request.client.host if request.client else "unknown",
            success=False,
            request_method=request.method,
            response_status=503,
            error_message=f"No API key configured for {service}",
            user_agent=request.headers.get("user-agent"),
        )
        raise HTTPException(
            status_code=503,
            detail=f"No API key configured for {service}. Add key with: python cli.py add-key --service {service}",
        )

    if service == "telegram":
        metadata["token"] = api_key

    target_url = get_target_url(service, path, metadata)
    query_params = dict(request.query_params)

    if service == "gemini":
        query_params["key"] = api_key
        
    if service == "trello":
        query_params["key"] = api_key
        # Check if we have token in metadata from the proxy setup
        if metadata and metadata.get("token"):
            query_params["token"] = metadata["token"]
        else:
            # Fallback to secondary secrets from DB (since token is sensitive)
            from app.db import database
            secondary_secrets = database.get_secondary_secrets(service)
            if secondary_secrets and secondary_secrets.get("token"):
                query_params["token"] = secondary_secrets["token"]

    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "authorization", "content-length", "x-proxy-auth")
    }

    if service != "gemini":
        auth_header = get_auth_header(service, api_key, metadata)
        if auth_header:
            config = SERVICE_CONFIGS.get(service, {})
            header_name = config.get("header_name", "Authorization")
            forward_headers[header_name] = auth_header

    header_overrides = {
        "github": {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        "openrouter": {
            "HTTP-Referer": request.headers.get("referer", "https://keyrelay.local"),
            "X-Title": "KeyRelay Proxy",
        },
        "anthropic": {"anthropic-version": "2023-06-01"},
        "replicate": {"Prefer": "wait"},
        "notion": {"Notion-Version": "2022-06-28"},
    }
    if service in header_overrides:
        forward_headers.update(header_overrides[service])
    forward_headers.setdefault("Accept", "application/json")

    timeout = httpx.Timeout(connect=10.0, read=120.0, write=120.0, pool=30.0)
    client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    has_body = request.method in {"POST", "PUT", "PATCH", "DELETE"}
    request_content = request.stream() if has_body else None
    username = user.get("username", "unknown")
    logger.info("Proxying %s %s for user=%s", request.method, target_url, username)

    try:
        upstream_response = await client.send(
            client.build_request(
                method=request.method,
                url=target_url,
                params=query_params,
                headers=forward_headers,
                content=request_content,
            ),
            stream=True,
        )
    except httpx.TimeoutException:
        await client.aclose()
        log_request(
            service=service,
            endpoint=f"/{path}",
            client_ip=request.client.host if request.client else "unknown",
            success=False,
            request_method=request.method,
            response_status=504,
            error_message="Gateway timeout",
            user_agent=request.headers.get("user-agent"),
        )
        raise HTTPException(status_code=504, detail="Gateway timeout")
    except httpx.ConnectError as exc:
        await client.aclose()
        log_request(
            service=service,
            endpoint=f"/{path}",
            client_ip=request.client.host if request.client else "unknown",
            success=False,
            request_method=request.method,
            response_status=502,
            error_message=f"Connection error: {exc}",
            user_agent=request.headers.get("user-agent"),
        )
        raise HTTPException(status_code=502, detail="Bad gateway")
    except Exception as exc:
        await client.aclose()
        log_request(
            service=service,
            endpoint=f"/{path}",
            client_ip=request.client.host if request.client else "unknown",
            success=False,
            request_method=request.method,
            response_status=500,
            error_message=f"Proxy error: {exc}",
            user_agent=request.headers.get("user-agent"),
        )
        raise HTTPException(status_code=500, detail="Internal proxy error")

    log_request(
        service=service,
        endpoint=f"/{path}",
        client_ip=request.client.host if request.client else "unknown",
        success=upstream_response.status_code < 400,
        request_method=request.method,
        response_status=upstream_response.status_code,
        user_agent=request.headers.get("user-agent"),
    )

    response_headers = {
        key: value
        for key, value in upstream_response.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }

    return StreamingResponse(
        upstream_response.aiter_raw(),
        status_code=upstream_response.status_code,
        headers=response_headers,
        background=BackgroundTask(_close_upstream, upstream_response, client),
    )


@router.api_route(
    "/{service}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def proxy_endpoint(
    request: Request,
    service: str,
    path: str,
    user: Dict[str, Any] = Depends(verify_proxy_access),
):
    return await proxy_request(request=request, service=service, path=path, user=user)
