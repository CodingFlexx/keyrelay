"""
Agent Vault Proxy v2 - Enhanced with Audit Logging and RBAC

A FastAPI-based proxy server that injects API keys into forwarded requests.
Features:
- SQLite database with encrypted API keys
- Comprehensive audit logging
- RBAC (Role-Based Access Control)
- 40+ supported services
"""

import json
import logging
import os
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Depends, Security
from fastapi.responses import Response, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import (
    init_database, get_api_key, list_api_keys,
    log_request, get_audit_logs, get_audit_stats,
    verify_api_key, DB_PATH, APP_DIR
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer(auto_error=False)

# Target URLs - Extended with 40+ services
TARGETS = {
    # LLM APIs
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
    
    # Vector Databases
    "pinecone": "https://api.pinecone.io",
    "weaviate": "https://{cluster}.weaviate.network",
    "qdrant": "https://{cluster}.cloud.qdrant.io",
    "chroma": "http://localhost:8000",
    "milvus": "https://{cluster}.milvus.io",
    "pgvector": "http://localhost:5432",
    "redis_vector": "http://localhost:6379",
    
    # Search & Data
    "brave": "https://api.search.brave.com",
    "serpapi": "https://serpapi.com",
    "tavily": "https://api.tavily.com",
    "exa": "https://api.exa.ai",
    "perplexity": "https://api.perplexity.ai",
    "bing": "https://api.bing.microsoft.com/v7.0",
    "google_custom_search": "https://www.googleapis.com/customsearch/v1",
    
    # Git & Dev
    "github": "https://api.github.com",
    "gitlab": "https://gitlab.com/api/v4",
    "bitbucket": "https://api.bitbucket.org/2.0",
    "azure_devops": "https://dev.azure.com",
    
    # Cloud & Storage
    "aws": "https://sts.amazonaws.com",
    "gcp": "https://cloud.googleapis.com",
    "azure": "https://management.azure.com",
    "supabase": "https://{project}.supabase.co",
    "firebase": "https://firebase.googleapis.com",
    "mongodb": "https://cloud.mongodb.com",
    "planetscale": "https://api.planetscale.com",
    "neon": "https://console.neon.tech/api/v2",
    "upstash": "https://api.upstash.com",
    
    # Communication
    "slack": "https://slack.com/api",
    "discord": "https://discord.com/api/v10",
    "telegram": "https://api.telegram.org",
    "twilio": "https://api.twilio.com/2010-04-01",
    "sendgrid": "https://api.sendgrid.com/v3",
    "mailgun": "https://api.mailgun.net/v3",
    "postmark": "https://api.postmarkapp.com",
    "resend": "https://api.resend.com",
    
    # Monitoring & Analytics
    "langsmith": "https://api.smith.langchain.com",
    "langfuse": "https://cloud.langfuse.com/api/public",
    "weights_biases": "https://api.wandb.ai",
    "arize": "https://api.arize.com",
    "phoenix": "https://app.phoenix.arize.com",
    "promptlayer": "https://api.promptlayer.com",
    "helicone": "https://api.hconeai.com",
    
    # Image & Media
    "replicate": "https://api.replicate.com/v1",
    "stability": "https://api.stability.ai/v2beta",
    "cloudinary": "https://api.cloudinary.com/v1_1",
    "imgix": "https://api.imgix.com",
    "unsplash": "https://api.unsplash.com",
    
    # Other AI Services
    "huggingface": "https://api-inference.huggingface.co",
    "assemblyai": "https://api.assemblyai.com/v2",
    "elevenlabs": "https://api.elevenlabs.io/v1",
    "openvoice": "https://api.openvoice.com",
    "whisper": "https://api.openai.com/v1",
    "deepgram": "https://api.deepgram.com/v1",
    "rev_ai": "https://api.rev.ai",
    
    # Productivity & Collaboration
    "notion": "https://api.notion.com/v1",
    "airtable": "https://api.airtable.com/v0",
    "trello": "https://api.trello.com/1",
    "asana": "https://app.asana.com/api/1.0",
    "linear": "https://api.linear.app/graphql",
    "jira": "https://api.atlassian.com",
    "confluence": "https://api.atlassian.com",
    
    # Payment & Commerce
    "stripe": "https://api.stripe.com/v1",
    "paypal": "https://api.paypal.com/v1",
    "shopify": "https://{shop}.myshopify.com/admin/api/2024-01",
    
    # Security & Auth
    "auth0": "https://{domain}.auth0.com",
    "okta": "https://{domain}.okta.com",
    "1password": "https://api.1password.com",
}

# Service configurations
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


def get_auth_header(service: str, api_key: str, metadata: Optional[Dict] = None) -> Optional[str]:
    """Get the Authorization header value for a service."""
    
    config = SERVICE_CONFIGS.get(service, {})
    auth_type = config.get("auth_type", "bearer")
    
    if auth_type == "bearer":
        return f"Bearer {api_key}"
    elif auth_type == "token":
        return f"Token {api_key}"
    elif auth_type == "basic":
        import base64
        account_sid = metadata.get('account_sid', '') if metadata else ''
        credentials = base64.b64encode(f"{account_sid}:{api_key}".encode()).decode()
        return f"Basic {credentials}"
    elif service == "github":
        return f"token {api_key}"
    elif service == "huggingface":
        return f"Bearer {api_key}"
    elif service == "telegram":
        return None  # Telegram uses token in URL
    
    return f"Bearer {api_key}"


def get_target_url(service: str, path: str, metadata: Optional[Dict] = None) -> str:
    """Build target URL with dynamic substitutions."""
    
    base = TARGETS.get(service, "")
    
    # Handle dynamic URLs
    if metadata:
        if "{resource}" in base and metadata.get('resource'):
            base = base.format(resource=metadata['resource'])
        if "{cluster}" in base and metadata.get('cluster'):
            base = base.format(cluster=metadata['cluster'])
        if "{project}" in base and metadata.get('project'):
            base = base.format(project=metadata['project'])
        if "{region}" in base and metadata.get('region'):
            base = base.format(region=metadata['region'])
        if "{domain}" in base and metadata.get('domain'):
            base = base.format(domain=metadata['domain'])
        if "{shop}" in base and metadata.get('shop'):
            base = base.format(shop=metadata['shop'])
    
    # Special cases
    if service == "telegram" and metadata and metadata.get('token'):
        return f"{base}/bot{metadata['token']}/{path}"
    
    # Chroma: Allow custom host via metadata or environment
    if service == "chroma":
        chroma_host = os.getenv("CHROMA_HOST", "localhost")
        chroma_port = os.getenv("CHROMA_PORT", "8000")
        base = f"http://{chroma_host}:{chroma_port}"
    
    return f"{base}/{path}"


async def verify_proxy_access(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> Dict[str, Any]:
    """Verify proxy access via API key."""
    
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Missing proxy API key. Set AGENT_VAULT_KEY environment variable or provide via Authorization header."
        )
    
    # Check if using environment variable bypass (for local development)
    env_key = os.getenv("AGENT_VAULT_PROXY_KEY")
    if env_key and credentials.credentials == env_key:
        return {"username": "system", "role": "admin"}
    
    # Verify against database
    user = verify_api_key(credentials.credentials)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    
    return user


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load secrets on startup with graceful shutdown."""
    logger.info("Initializing Agent Vault Proxy v2...")
    
    # Initialize database if needed
    if not DB_PATH.exists():
        logger.info("Database not found, initializing...")
        init_database()
    
    logger.info(f"Database location: {DB_PATH}")
    logger.info(f"Available services: {len(TARGETS)}")
    
    # Setup signal handlers for graceful shutdown
    import signal
    
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, initiating graceful shutdown...")
        # Close any open connections
        logger.info("Graceful shutdown complete")
        import sys
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    yield
    
    logger.info("Shutting down...")
    logger.info("Cleanup complete")


app = FastAPI(
    title="Agent Vault Proxy v2",
    description="Secure API Key Injection Proxy with Audit Logging and RBAC",
    version="2.0.0",
    lifespan=lifespan,
)


async def proxy_request(
    service: str,
    path: str,
    method: str,
    headers: dict,
    body: Optional[bytes],
    query_params: dict,
    client_ip: str,
    user: Dict[str, Any]
) -> Response:
    """Proxy a request to the target service with injected auth."""
    
    if service not in TARGETS:
        # Log failed request
        log_request(
            service=service,
            endpoint=f"/{path}",
            client_ip=client_ip,
            success=False,
            request_method=method,
            response_status=404,
            error_message="Unknown service"
        )
        raise HTTPException(status_code=404, detail=f"Unknown service: {service}")
    
    # Get API key from database
    api_key = get_api_key(service)
    if not api_key:
        log_request(
            service=service,
            endpoint=f"/{path}",
            client_ip=client_ip,
            success=False,
            request_method=method,
            response_status=503,
            error_message=f"No API key configured for {service}"
        )
        raise HTTPException(
            status_code=503,
            detail=f"No API key configured for {service}. Add key with: python cli_v2.py add-key {service}"
        )
    
    # Build target URL
    target_url = get_target_url(service, path)
    
    # Handle query params
    if query_params:
        query_string = "&".join(f"{k}={v}" for k, v in query_params.items())
        target_url = f"{target_url}?{query_string}"
    
    # Prepare headers
    forward_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in ("host", "authorization", "content-length", "x-proxy-auth")
    }
    
    # Inject auth (header or query param)
    if service == "gemini":
        # Gemini uses query parameter, not Bearer token
        separator = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{separator}key={api_key}"
        logger.info(f"Injected Gemini API key as query parameter")
    else:
        auth_header = get_auth_header(service, api_key)
        if auth_header:
            forward_headers["Authorization"] = auth_header
            logger.info(f"Injected auth for {service}")
    
    # Service-specific headers
    header_overrides = {
        "github": {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        },
        "openrouter": {
            "HTTP-Referer": headers.get("referer", "https://agent-vault.local"),
            "X-Title": "Agent Vault Proxy"
        },
        "anthropic": {"anthropic-version": "2023-06-01"},
        "replicate": {"Prefer": "wait"},
        "notion": {"Notion-Version": "2022-06-28"},
        "airtable": {},
    }
    
    if service in header_overrides:
        forward_headers.update(header_overrides[service])
    
    # Add Accept header
    forward_headers.setdefault("Accept", "application/json")
    
    logger.info(f"Proxying {method} {target_url} for user {user.get('username', 'unknown')}")
    
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
            
            # Log successful request
            log_request(
                service=service,
                endpoint=f"/{path}",
                client_ip=client_ip,
                success=response.status_code < 400,
                request_method=method,
                response_status=response.status_code,
                user_agent=headers.get("user-agent")
            )
            
            logger.info(f"Response: {response.status_code}")
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
        except httpx.TimeoutException:
            logger.error(f"Timeout proxying to {service}")
            log_request(
                service=service,
                endpoint=f"/{path}",
                client_ip=client_ip,
                success=False,
                request_method=method,
                error_message="Gateway timeout"
            )
            raise HTTPException(status_code=504, detail="Gateway timeout")
        except httpx.ConnectError as e:
            logger.error(f"Connection error: {e}")
            log_request(
                service=service,
                endpoint=f"/{path}",
                client_ip=client_ip,
                success=False,
                request_method=method,
                error_message=f"Connection error: {str(e)}"
            )
            raise HTTPException(status_code=502, detail="Bad gateway")


@app.api_route(
    "/{service}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    dependencies=[Depends(verify_proxy_access)]
)
async def proxy_endpoint(
    request: Request,
    service: str,
    path: str,
    user: Dict[str, Any] = Depends(verify_proxy_access)
):
    """Main proxy endpoint for all services."""
    
    body = await request.body()
    query_params = dict(request.query_params)
    client_ip = request.client.host if request.client else "unknown"
    
    return await proxy_request(
        service=service,
        path=path,
        method=request.method,
        headers=dict(request.headers),
        body=body if body else None,
        query_params=query_params,
        client_ip=client_ip,
        user=user
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    keys = list_api_keys()
    return {
        "status": "healthy",
        "version": "2.0.0",
        "services_available": len(TARGETS),
        "services_configured": len(keys),
        "configured_services": [k['service_name'] for k in keys],
        "features": ["encryption", "audit_logging", "rbac"]
    }


@app.get("/health/services")
async def services_health_check():
    """Detailed health check for all configured services."""
    import httpx
    
    keys = list_api_keys()
    service_status = {}
    
    # Simple health check endpoints for common services
    health_endpoints = {
        "openrouter": ("https://openrouter.ai/api/v1/models", 200),
        "openai": ("https://api.openai.com/v1/models", 401),  # 401 expected without key
        "anthropic": ("https://api.anthropic.com/v1/models", 401),
        "groq": ("https://api.groq.com/openai/v1/models", 401),
        "github": ("https://api.github.com", 200),
        "huggingface": ("https://api-inference.huggingface.co/status", 200),
    }
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for key_info in keys:
            service = key_info['service_name']
            if service in health_endpoints:
                url, expected_status = health_endpoints[service]
                try:
                    response = await client.get(url)
                    # 401 is OK (means service is up, just needs auth)
                    is_healthy = response.status_code in (200, expected_status, 401)
                    service_status[service] = {
                        "status": "healthy" if is_healthy else "degraded",
                        "http_status": response.status_code,
                        "response_time_ms": int(response.elapsed.total_seconds() * 1000)
                    }
                except Exception as e:
                    service_status[service] = {
                        "status": "unreachable",
                        "error": str(e)
                    }
            else:
                service_status[service] = {
                    "status": "configured",
                    "note": "No automated health check available"
                }
    
    return {
        "status": "healthy",
        "services_checked": len(service_status),
        "services": service_status
    }


@app.get("/")
async def root():
    """Root endpoint with usage info."""
    return {
        "name": "Agent Vault Proxy v2",
        "version": "2.0.0",
        "description": "Secure API Key Injection Proxy with Audit Logging and RBAC",
        "features": {
            "encryption": "AES-128-CBC + HMAC via Fernet",
            "audit_logging": "SQLite-based request logging",
            "rbac": "admin/user role support",
            "services": len(TARGETS)
        },
        "endpoints": {
            "proxy": "/{service}/{path} - Proxy requests with auth injection",
            "health": "/health - Health check",
            "audit": "/audit - View audit logs (admin only)"
        },
        "cli": "python cli_v2.py - Manage keys and users",
        "docs": "/docs - OpenAPI documentation"
    }


# Admin-only endpoints

@app.get("/admin/audit-logs")
async def admin_audit_logs(
    service: Optional[str] = None,
    limit: int = 100,
    user: Dict[str, Any] = Depends(verify_proxy_access)
):
    """Get audit logs (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = get_audit_logs(service=service, limit=limit)
    return {"logs": logs, "count": len(logs)}


@app.get("/admin/audit-stats")
async def admin_audit_stats(
    user: Dict[str, Any] = Depends(verify_proxy_access)
):
    """Get audit statistics (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return get_audit_stats()


@app.get("/admin/services")
async def admin_services(
    user: Dict[str, Any] = Depends(verify_proxy_access)
):
    """List all available services (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {
        "services": list(TARGETS.keys()),
        "count": len(TARGETS)
    }


@app.post("/admin/validate-key/{service}")
async def validate_service_key(
    service: str,
    user: Dict[str, Any] = Depends(verify_proxy_access)
):
    """Validate API key for a service by making a test request (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if service not in TARGETS:
        raise HTTPException(status_code=404, detail=f"Unknown service: {service}")
    
    api_key = get_api_key(service)
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail=f"No API key configured for {service}"
        )
    
    # Test endpoints for validation
    test_endpoints = {
        "openrouter": ("https://openrouter.ai/api/v1/models", "GET"),
        "openai": ("https://api.openai.com/v1/models", "GET"),
        "anthropic": ("https://api.anthropic.com/v1/models", "GET"),
        "groq": ("https://api.groq.com/openai/v1/models", "GET"),
        "github": ("https://api.github.com/user", "GET"),
        "huggingface": ("https://api-inference.huggingface.co/status", "GET"),
        "gemini": ("https://generativelanguage.googleapis.com/v1beta/models", "GET"),
    }
    
    if service not in test_endpoints:
        return {
            "service": service,
            "status": "unknown",
            "message": "No validation endpoint configured for this service"
        }
    
    url, method = test_endpoints[service]
    
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            # Build headers with auth
            headers = {"Accept": "application/json"}
            
            if service == "gemini":
                url = f"{url}?key={api_key}"
            else:
                auth_header = get_auth_header(service, api_key)
                if auth_header:
                    headers["Authorization"] = auth_header
            
            response = await client.request(method, url, headers=headers)
            
            # 200 = valid, 401 = invalid key, 403 = key valid but no access
            is_valid = response.status_code == 200
            is_auth_error = response.status_code in (401, 403)
            
            result = {
                "service": service,
                "status": "valid" if is_valid else ("invalid_key" if is_auth_error else "error"),
                "http_status": response.status_code,
                "response_time_ms": int(response.elapsed.total_seconds() * 1000)
            }
            
            if is_auth_error:
                result["message"] = "API key is invalid or expired"
            elif not is_valid:
                result["message"] = f"Unexpected response: {response.status_code}"
            else:
                result["message"] = "API key is valid and working"
            
            return result
            
        except httpx.TimeoutException:
            return {
                "service": service,
                "status": "timeout",
                "message": "Request timed out"
            }
        except Exception as e:
            return {
                "service": service,
                "status": "error",
                "message": str(e)
            }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)