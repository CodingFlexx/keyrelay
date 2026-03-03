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

# Target URLs - Extended with common AI and API services
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
    
    # Search & Data
    "brave": "https://api.search.brave.com",
    "serpapi": "https://serpapi.com",
    "tavily": "https://api.tavily.com",
    
    # Git & Dev
    "github": "https://api.github.com",
    "gitlab": "https://gitlab.com/api/v4",
    
    # Cloud & Storage
    "aws": "https://sts.amazonaws.com",  # Placeholder - AWS uses SDK
    
    # Communication
    "slack": "https://slack.com/api",
    "discord": "https://discord.com/api/v10",
    "telegram": "https://api.telegram.org",
    
    # Monitoring & Analytics
    "langsmith": "https://api.smith.langchain.com",
}

# Secrets storage
_secrets: dict = {}


def load_secrets() -> dict:
    """Load secrets from environment variables or secrets.json file."""
    secrets = {}
    
    # Environment variable mappings
    env_mappings = {
        "openrouter": ("OPENROUTER_API_KEY", "api_key"),
        "openai": ("OPENAI_API_KEY", "api_key"),
        "anthropic": ("ANTHROPIC_API_KEY", "api_key"),
        "gemini": ("GEMINI_API_KEY", "api_key"),
        "groq": ("GROQ_API_KEY", "api_key"),
        "cohere": ("COHERE_API_KEY", "api_key"),
        "mistral": ("MISTRAL_API_KEY", "api_key"),
        "deepseek": ("DEEPSEEK_API_KEY", "api_key"),
        "brave": ("BRAVE_API_KEY", "api_key"),
        "serpapi": ("SERPAPI_KEY", "api_key"),
        "tavily": ("TAVILY_API_KEY", "api_key"),
        "github": ("GITHUB_PAT", "pat"),
        "gitlab": ("GITLAB_TOKEN", "token"),
        "slack": ("SLACK_TOKEN", "token"),
        "discord": ("DISCORD_TOKEN", "token"),
        "telegram": ("TELEGRAM_BOT_TOKEN", "token"),
        "langsmith": ("LANGSMITH_API_KEY", "api_key"),
    }
    
    # Try environment variables first
    for service, (env_var, key_name) in env_mappings.items():
        value = os.getenv(env_var)
        if value:
            secrets[service] = {key_name: value}
            logger.info(f"Loaded {service} key from environment")
    
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
    
    # Bearer token services
    bearer_services = [
        "openrouter", "openai", "anthropic", "gemini", "groq",
        "cohere", "mistral", "deepseek", "brave", "serpapi",
        "tavily", "gitlab", "langsmith"
    ]
    
    # Token-based services (different formats)
    if service in bearer_services:
        return f"Bearer {_secrets[service]['api_key']}"
    elif service == "github":
        return f"token {_secrets[service]['pat']}"
    elif service == "slack":
        return f"Bearer {_secrets[service]['token']}"
    elif service == "discord":
        return f"Bot {_secrets[service]['token']}"
    elif service == "telegram":
        # Telegram uses bot token in URL, not header
        return None
    
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
    
    # Handle service-specific URL modifications
    if service == "gemini" and "api_key" in _secrets.get(service, {}):
        query_params = {**query_params, "key": _secrets[service]["api_key"]}
    elif service == "telegram" and "token" in _secrets.get(service, {}):
        # Telegram uses /bot{token}/path format
        target_url = f"{target_base}/bot{_secrets[service]['token']}/{path}"
    
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
    elif service == "anthropic":
        forward_headers["anthropic-version"] = "2023-06-01"
    elif service == "gemini":
        # Gemini uses API key in query param, handled separately
        pass
    elif service == "cohere":
        forward_headers["Accept"] = "application/json"
    elif service == "gitlab":
        forward_headers["Accept"] = "application/json"
    elif service == "slack":
        forward_headers["Accept"] = "application/json"
    elif service == "discord":
        forward_headers["Accept"] = "application/json"
    elif service == "langsmith":
        forward_headers["Accept"] = "application/json"
    
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
        "version": "1.1.0",
        "description": "Secure API Key Injection Proxy for 15+ AI Services",
        "services": {
            # LLM APIs
            "openrouter": "OpenRouter (unified LLM access)",
            "openai": "OpenAI (GPT-4, etc.)",
            "anthropic": "Anthropic (Claude)",
            "gemini": "Google Gemini",
            "groq": "Groq (fast inference)",
            "cohere": "Cohere",
            "mistral": "Mistral AI",
            "deepseek": "DeepSeek",
            # Search
            "brave": "Brave Search",
            "serpapi": "SerpAPI (Google Search)",
            "tavily": "Tavily (AI search)",
            # Git
            "github": "GitHub API",
            "gitlab": "GitLab API",
            # Communication
            "slack": "Slack API",
            "discord": "Discord API",
            "telegram": "Telegram Bot API",
            # Monitoring
            "langsmith": "LangSmith (LLM tracing)",
        },
        "usage": "POST/GET /{service}/{api-path} - Auth headers injected automatically",
        "health": "/health - Check configured services",
        "docs": "/docs - OpenAPI documentation"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
