"""
KeyRelay Proxy v0.9 - with audit logging, RBAC and middleware hardening.
"""

import base64
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.background import BackgroundTask

from database import (
    DB_PATH,
    get_api_key,
    get_audit_logs,
    get_audit_stats,
    get_service_metadata,
    init_database,
    list_api_keys,
    log_request,
    verify_api_key,
)
from middleware import LoggingMiddleware, RateLimitMiddleware, SecurityMiddleware


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

TARGETS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
    "groq": "https://api.groq.com/openai/v1",
    "cohere": "https://api.cohere.com/v1",
    "mistral": "https://api.mistral.ai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "azure_openai": "https://{resource}.openai.azure.com/openai",
    "aws_bedrock": "https://bedrock-runtime.{region}.amazonaws.com",
    "ai21": "https://api.ai21.com/studio/v1",
    "aleph_alpha": "https://api.aleph-alpha.com",
    "pinecone": "https://api.pinecone.io",
    "weaviate": "https://{cluster}.weaviate.network",
    "qdrant": "https://{cluster}.cloud.qdrant.io",
    "chroma": "http://localhost:8000",
    "milvus": "https://{cluster}.milvus.io",
    "pgvector": "http://localhost:5432",
    "redis_vector": "http://localhost:6379",
    "brave": "https://api.search.brave.com",
    "serpapi": "https://serpapi.com",
    "tavily": "https://api.tavily.com",
    "exa": "https://api.exa.ai",
    "perplexity": "https://api.perplexity.ai",
    "bing": "https://api.bing.microsoft.com/v7.0",
    "google_custom_search": "https://www.googleapis.com/customsearch/v1",
    "github": "https://api.github.com",
    "gitlab": "https://gitlab.com/api/v4",
    "bitbucket": "https://api.bitbucket.org/2.0",
    "azure_devops": "https://dev.azure.com",
    "aws": "https://sts.amazonaws.com",
    "gcp": "https://cloud.googleapis.com",
    "azure": "https://management.azure.com",
    "supabase": "https://{project}.supabase.co",
    "firebase": "https://firebase.googleapis.com",
    "mongodb": "https://cloud.mongodb.com",
    "planetscale": "https://api.planetscale.com",
    "neon": "https://console.neon.tech/api/v2",
    "upstash": "https://api.upstash.com",
    "slack": "https://slack.com/api",
    "discord": "https://discord.com/api/v10",
    "telegram": "https://api.telegram.org",
    "twilio": "https://api.twilio.com/2010-04-01",
    "sendgrid": "https://api.sendgrid.com/v3",
    "mailgun": "https://api.mailgun.net/v3",
    "postmark": "https://api.postmarkapp.com",
    "resend": "https://api.resend.com",
    "langsmith": "https://api.smith.langchain.com",
    "langfuse": "https://cloud.langfuse.com/api/public",
    "weights_biases": "https://api.wandb.ai",
    "arize": "https://api.arize.com",
    "phoenix": "https://app.phoenix.arize.com",
    "promptlayer": "https://api.promptlayer.com",
    "helicone": "https://api.hconeai.com",
    "replicate": "https://api.replicate.com/v1",
    "stability": "https://api.stability.ai/v2beta",
    "cloudinary": "https://api.cloudinary.com/v1_1",
    "imgix": "https://api.imgix.com",
    "unsplash": "https://api.unsplash.com",
    "huggingface": "https://api-inference.huggingface.co",
    "assemblyai": "https://api.assemblyai.com/v2",
    "elevenlabs": "https://api.elevenlabs.io/v1",
    "openvoice": "https://api.openvoice.com",
    "whisper": "https://api.openai.com/v1",
    "deepgram": "https://api.deepgram.com/v1",
    "rev_ai": "https://api.rev.ai",
    "notion": "https://api.notion.com/v1",
    "airtable": "https://api.airtable.com/v0",
    "trello": "https://api.trello.com/1",
    "asana": "https://app.asana.com/api/1.0",
    "linear": "https://api.linear.app/graphql",
    "jira": "https://api.atlassian.com",
    "confluence": "https://api.atlassian.com",
    "stripe": "https://api.stripe.com/v1",
    "paypal": "https://api.paypal.com/v1",
    "shopify": "https://{shop}.myshopify.com/admin/api/2024-01",
    "auth0": "https://{domain}.auth0.com",
    "okta": "https://{domain}.okta.com",
    "1password": "https://api.1password.com",
}

SERVICE_CONFIGS = {
    "notion": {"auth_type": "bearer", "header_name": "Authorization"},
    "airtable": {"auth_type": "bearer", "header_name": "Authorization"},
    "twilio": {"auth_type": "basic", "header_name": "Authorization"},
    "sendgrid": {"auth_type": "bearer", "header_name": "Authorization"},
    "stripe": {"auth_type": "bearer", "header_name": "Authorization"},
    "auth0": {"auth_type": "bearer", "header_name": "Authorization"},
    "shopify": {"auth_type": "bearer", "header_name": "X-Shopify-Access-Token"},
    "deepgram": {"auth_type": "bearer", "header_name": "Authorization"},
    "linear": {"auth_type": "bearer", "header_name": "Authorization"},
    "replicate": {"auth_type": "token", "header_name": "Authorization"},
}

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_auth_header(service: str, api_key: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Get Authorization value for a service."""
    if service == "github":
        return f"token {api_key}"
    if service == "telegram":
        return None

    config = SERVICE_CONFIGS.get(service, {})
    auth_type = config.get("auth_type", "bearer")

    if auth_type == "bearer":
        return f"Bearer {api_key}"
    if auth_type == "token":
        return f"Token {api_key}"
    if auth_type == "basic":
        account_sid = metadata.get("account_sid", "") if metadata else ""
        credentials = base64.b64encode(f"{account_sid}:{api_key}".encode()).decode()
        return f"Basic {credentials}"
    return f"Bearer {api_key}"


def get_target_url(service: str, path: str, metadata: Optional[Dict[str, Any]] = None) -> str:
    """Build target URL with dynamic substitutions."""
    base = TARGETS.get(service, "")

    if metadata and metadata.get("base_url"):
        base = metadata["base_url"]

    if metadata:
        if "{resource}" in base and metadata.get("resource"):
            base = base.replace("{resource}", str(metadata["resource"]))
        if "{cluster}" in base and metadata.get("cluster"):
            base = base.replace("{cluster}", str(metadata["cluster"]))
        if "{project}" in base and metadata.get("project"):
            base = base.replace("{project}", str(metadata["project"]))
        if "{region}" in base and metadata.get("region"):
            base = base.replace("{region}", str(metadata["region"]))
        if "{domain}" in base and metadata.get("domain"):
            base = base.replace("{domain}", str(metadata["domain"]))
        if "{shop}" in base and metadata.get("shop"):
            base = base.replace("{shop}", str(metadata["shop"]))

    if service == "telegram" and metadata and metadata.get("token"):
        return f"{base}/bot{metadata['token']}/{path}"

    if service == "chroma":
        chroma_host = os.getenv("CHROMA_HOST", "localhost")
        chroma_port = os.getenv("CHROMA_PORT", "8000")
        base = f"http://{chroma_host}:{chroma_port}"

    return f"{base}/{path}"


async def verify_proxy_access(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> Dict[str, Any]:
    """Verify access token unless explicitly disabled."""
    require_auth = _env_bool("REQUIRE_AGENT_AUTH", True)
    if not require_auth:
        return {"username": "anonymous-dev", "role": "user"}

    if not credentials:
        raise HTTPException(
            status_code=401,
            detail=(
                "Missing proxy API key. Provide Authorization: Bearer <key> "
                "or set REQUIRE_AGENT_AUTH=false for local development."
            ),
        )

    env_key = os.getenv("AGENT_VAULT_PROXY_KEY")
    if env_key and credentials.credentials == env_key:
        return {"username": "system", "role": "admin"}

    user = verify_api_key(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing KeyRelay v0.9.1...")
    if not DB_PATH.exists():
        logger.info("Database not found, initializing...")
        init_database()
    logger.info("Available services: %s", len(TARGETS))
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="KeyRelay Proxy",
    description="Secure API Key Injection Proxy with Audit Logging and RBAC",
    version="0.9.1",
    lifespan=lifespan,
)

app.add_middleware(SecurityMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware, requests_per_minute=60, burst_size=10)
_cors_origins = [
    o.strip()
    for o in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


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


@app.get("/")
async def root():
    return {
        "name": "KeyRelay Proxy",
        "version": "0.9.1",
        "description": "Secure API Key Injection Proxy with Audit Logging and RBAC",
        "endpoints": {
            "proxy": "/{service}/{path} - Proxy requests with auth injection",
            "health": "/health - Health check",
            "audit": "/admin/audit-logs - View audit logs (admin only)",
        },
        "cli": "python cli.py - Manage keys and users",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    keys = list_api_keys()
    return {
        "status": "healthy",
        "version": "0.9.1",
        "services_available": len(TARGETS),
        "services_configured": len(keys),
        "configured_services": [k["service_name"] for k in keys],
        "features": ["encryption", "audit_logging", "rbac", "streaming_proxy"],
    }


@app.get("/health/services")
async def services_health_check(user: Dict[str, Any] = Depends(verify_proxy_access)):
    keys = list_api_keys()
    service_status: Dict[str, Any] = {}
    health_endpoints = {
        "openrouter": "https://openrouter.ai/api/v1/models",
        "openai": "https://api.openai.com/v1/models",
        "anthropic": "https://api.anthropic.com/v1/models",
        "groq": "https://api.groq.com/openai/v1/models",
        "github": "https://api.github.com",
        "huggingface": "https://api-inference.huggingface.co/status",
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        for key_info in keys:
            service = key_info["service_name"]
            if service not in health_endpoints:
                service_status[service] = {
                    "status": "configured",
                    "note": "No automated health check available",
                }
                continue

            try:
                response = await client.get(health_endpoints[service])
                service_status[service] = {
                    "status": "healthy" if response.status_code in (200, 401, 403) else "degraded",
                    "http_status": response.status_code,
                    "response_time_ms": int(response.elapsed.total_seconds() * 1000),
                }
            except Exception as exc:
                service_status[service] = {"status": "unreachable", "error": str(exc)}

    return {"status": "healthy", "services_checked": len(service_status), "services": service_status}


@app.get("/admin/audit-logs")
async def admin_audit_logs(
    service: Optional[str] = None,
    limit: int = 100,
    user: Dict[str, Any] = Depends(verify_proxy_access),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    limit = max(1, min(limit, 10000))
    logs = get_audit_logs(service=service, limit=limit)
    return {"logs": logs, "count": len(logs)}


@app.get("/admin/audit-stats")
async def admin_audit_stats(user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_audit_stats()


@app.get("/admin/services")
async def admin_services(user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"services": list(TARGETS.keys()), "count": len(TARGETS)}


@app.api_route(
    "/{service}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def proxy_endpoint(
    request: Request,
    service: str,
    path: str,
    user: Dict[str, Any] = Depends(verify_proxy_access),
):
    return await proxy_request(request=request, service=service, path=path, user=user)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
