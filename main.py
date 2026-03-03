"""
Agent Vault Proxy - Secure API Key Injection Proxy

A FastAPI-based proxy server that injects API keys into forwarded requests.
Keys are stored locally in secrets.json and never exposed to clients.
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, StreamingResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration - can be overridden via env var
SECRETS_FILE = Path(os.getenv("SECRETS_FILE", "secrets.json"))

# Target URLs
TARGETS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "github": "https://api.github.com",
    "brave": "https://api.search.brave.com",
}

# Secrets storage
_secrets: dict = {}


def load_secrets() -> dict:
    """Load secrets from environment variables or secrets.json file."""
    secrets = {}
    
    # Try environment variables first (for Docker/container setups)
    openrouter_key = os.getenv("OPENROUTER_API_KEY")
    github_pat = os.getenv("GITHUB_PAT")
    brave_key = os.getenv("BRAVE_API_KEY")
    
    if openrouter_key:
        secrets["openrouter"] = {"api_key": openrouter_key}
        logger.info("Loaded OpenRouter key from environment")
    
    if github_pat:
        secrets["github"] = {"pat": github_pat}
        logger.info("Loaded GitHub PAT from environment")
    
    if brave_key:
        secrets["brave"] = {"api_key": brave_key}
        logger.info("Loaded Brave key from environment")
    
    # Fallback to secrets.json if no env vars
    if not secrets and SECRETS_FILE.exists():
        logger.info(f"Loading secrets from {SECRETS_FILE}")
        with open(SECRETS_FILE) as f:
            secrets = json.load(f)
    elif not secrets:
        logger.error(f"No secrets found. Set env vars or create {SECRETS_FILE}")
        raise FileNotFoundError(
            f"Create {SECRETS_FILE} from secrets.json.example or set environment variables"
        )
    
    return secrets


def get_auth_header(service: str) -> Optional[str]:
    """Get the Authorization header value for a service."""
    if service not in _secrets:
        return None
    
    if service == "openrouter":
        return f"Bearer {_secrets[service]['api_key']}"
    elif service == "github":
        return f"token {_secrets[service]['pat']}"
    elif service == "brave":
        return f"Bearer {_secrets[service]['api_key']}"
    
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load secrets on startup."""
    global _secrets
    logger.info("Loading secrets...")
    _secrets = load_secrets()
    logger.info(f"Loaded secrets for: {list(_secrets.keys())}")
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="Agent Vault Proxy",
    description="Secure API Key Injection Proxy for Agent Services",
    version="1.0.0",
    lifespan=lifespan,
)


async def proxy_request(
    service: str,
    path: str,
    method: str,
    headers: dict,
    body: Optional[bytes],
    query_params: dict
) -> Response:
    """Proxy a request to the target service with injected auth."""
    
    if service not in TARGETS:
        raise HTTPException(status_code=404, detail=f"Unknown service: {service}")
    
    # Build target URL
    target_base = TARGETS[service]
    target_url = f"{target_base}/{path}"
    if query_params:
        query_string = "&".join(f"{k}={v}" for k, v in query_params.items())
        target_url = f"{target_url}?{query_string}"
    
    # Prepare headers
    forward_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in ("host", "authorization", "content-length")
    }
    
    # Inject auth header
    auth_header = get_auth_header(service)
    if auth_header:
        forward_headers["Authorization"] = auth_header
        logger.info(f"Injected auth for {service}")
    else:
        logger.warning(f"No auth configured for {service}")
    
    # Service-specific headers
    if service == "github":
        forward_headers["Accept"] = "application/vnd.github+json"
        forward_headers["X-GitHub-Api-Version"] = "2022-11-28"
    elif service == "openrouter":
        forward_headers["HTTP-Referer"] = headers.get("referer", "https://agent-vault.local")
        forward_headers["X-Title"] = "Agent Vault Proxy"
    
    logger.info(f"Proxying {method} {target_url}")
    
    # Make request
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body,
                follow_redirects=True
            )
            
            logger.info(f"Response: {response.status_code}")
            
            # Return response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
        except httpx.TimeoutException:
            logger.error(f"Timeout proxying to {service}")
            raise HTTPException(status_code=504, detail="Gateway timeout")
        except httpx.ConnectError as e:
            logger.error(f"Connection error: {e}")
            raise HTTPException(status_code=502, detail="Bad gateway")


@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_endpoint(request: Request, service: str, path: str):
    """Main proxy endpoint for all services."""
    
    # Read request body
    body = await request.body()
    
    # Get query params
    query_params = dict(request.query_params)
    
    # Proxy the request
    return await proxy_request(
        service=service,
        path=path,
        method=request.method,
        headers=dict(request.headers),
        body=body if body else None,
        query_params=query_params
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "services": list(TARGETS.keys()),
        "configured": list(_secrets.keys())
    }


@app.get("/")
async def root():
    """Root endpoint with usage info."""
    return {
        "name": "Agent Vault Proxy",
        "version": "1.0.0",
        "endpoints": {
            "/health": "Health check",
            "/openrouter/*": "Proxy to openrouter.ai/api/v1/*",
            "/github/*": "Proxy to api.github.com/*",
            "/brave/*": "Proxy to api.search.brave.com/*",
        },
        "usage": "Send requests to /{service}/{path} with your payload"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
