"""
Agent Vault Proxy - Secure API Key Injection Proxy

A FastAPI-based proxy server that injects API keys into forwarded requests.
Keys are stored securely in SQLite database and never exposed to clients.
"""

import asyncio
import json
import logging
import os
import sqlite3
import base64
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional, Dict

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet

from middleware import SecurityMiddleware, RateLimitMiddleware, LoggingMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration
APP_DIR = Path.home() / ".agent-vault"
DB_PATH = APP_DIR / "vault.db"
KEY_FILE = APP_DIR / ".master_key"

# Secrets storage
_secrets: dict = {}
_cipher: Optional[Fernet] = None


def _get_cipher() -> Fernet:
    """Get or initialize cipher for decryption."""
    global _cipher
    if _cipher is None:
        if not KEY_FILE.exists():
            raise RuntimeError("Vault not initialized. Run: ./cli.py init")
        with open(KEY_FILE, 'rb') as f:
            key = base64.urlsafe_b64decode(f.read())
        _cipher = Fernet(key)
    return _cipher


def _decrypt_key(encrypted: str) -> str:
    """Decrypt an API key."""
    cipher = _get_cipher()
    return cipher.decrypt(encrypted.encode()).decode()


def load_secrets_from_db() -> dict:
    """Load secrets from SQLite database."""
    secrets = {}
    
    if not DB_PATH.exists():
        logger.warning(f"Database not found: {DB_PATH}")
        logger.info("Run './cli.py init' to initialize the vault")
        return secrets
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Load keys
        cursor.execute('SELECT service, key_value FROM api_keys')
        rows = cursor.fetchall()
        
        # Load metadata
        cursor.execute('SELECT * FROM service_metadata')
        metadata_rows = cursor.fetchall()
        metadata = {}
        for row in metadata_rows:
            service = row[0]
            metadata[service] = {
                'cluster': row[1],
                'project': row[2],
                'resource': row[3],
                'cloud_name': row[4],
                'account_sid': row[5]
            }
        
        conn.close()
        
        for service, encrypted_key in rows:
            try:
                decrypted = _decrypt_key(encrypted_key)
                
                # Determine key type based on service
                if service == "github":
                    secrets[service] = {"pat": decrypted}
                elif service in ["slack", "discord", "telegram", "replicate", "huggingface"]:
                    secrets[service] = {"token": decrypted}
                else:
                    secrets[service] = {"api_key": decrypted}
                
                # Add metadata if available
                if service in metadata:
                    meta = metadata[service]
                    for key, value in meta.items():
                        if value:
                            secrets[service][key] = value
                
                logger.info(f"Loaded {service} key from database")
            except Exception as e:
                logger.error(f"Failed to decrypt key for {service}: {e}")
        
    except Exception as e:
        logger.error(f"Failed to load secrets from database: {e}")
    
    return secrets


def load_secrets() -> dict:
    """Load secrets from database with fallback to environment variables."""
    secrets = {}
    
    # Environment variable mappings (for Docker/production)
    env_mappings = {
        # LLM APIs
        "openrouter": ("OPENROUTER_API_KEY", "api_key"),
        "openai": ("OPENAI_API_KEY", "api_key"),
        "anthropic": ("ANTHROPIC_API_KEY", "api_key"),
        "gemini": ("GEMINI_API_KEY", "api_key"),
        "groq": ("GROQ_API_KEY", "api_key"),
        "cohere": ("COHERE_API_KEY", "api_key"),
        "mistral": ("MISTRAL_API_KEY", "api_key"),
        "deepseek": ("DEEPSEEK_API_KEY", "api_key"),
        "azure_openai": ("AZURE_OPENAI_API_KEY", "api_key"),
        "aws_bedrock": ("AWS_BEDROCK_KEY", "api_key"),
        
        # Vector DBs
        "pinecone": ("PINECONE_API_KEY", "api_key"),
        "weaviate": ("WEAVIATE_API_KEY", "api_key"),
        "qdrant": ("QDRANT_API_KEY", "api_key"),
        "chroma": ("CHROMA_API_KEY", "api_key"),
        "milvus": ("MILVUS_API_KEY", "api_key"),
        
        # Search
        "brave": ("BRAVE_API_KEY", "api_key"),
        "serpapi": ("SERPAPI_KEY", "api_key"),
        "tavily": ("TAVILY_API_KEY", "api_key"),
        "exa": ("EXA_API_KEY", "api_key"),
        "perplexity": ("PERPLEXITY_API_KEY", "api_key"),
        
        # Git
        "github": ("GITHUB_PAT", "pat"),
        "gitlab": ("GITLAB_TOKEN", "token"),
        "bitbucket": ("BITBUCKET_TOKEN", "token"),
        
        # Cloud
        "supabase": ("SUPABASE_KEY", "api_key"),
        "firebase": ("FIREBASE_TOKEN", "token"),
        
        # Communication
        "slack": ("SLACK_TOKEN", "token"),
        "discord": ("DISCORD_TOKEN", "token"),
        "telegram": ("TELEGRAM_BOT_TOKEN", "token"),
        "twilio": ("TWILIO_AUTH_TOKEN", "token"),
        "sendgrid": ("SENDGRID_API_KEY", "api_key"),
        
        # Monitoring
        "langsmith": ("LANGSMITH_API_KEY", "api_key"),
        "langfuse": ("LANGFUSE_PUBLIC_KEY", "api_key"),
        "weights_biases": ("WANDB_API_KEY", "api_key"),
        "arize": ("ARIZE_API_KEY", "api_key"),
        
        # Image & Media
        "replicate": ("REPLICATE_API_TOKEN", "token"),
        "stability": ("STABILITY_API_KEY", "api_key"),
        "cloudinary": ("CLOUDINARY_API_KEY", "api_key"),
        
        # Other AI
        "huggingface": ("HF_API_TOKEN", "token"),
        "assemblyai": ("ASSEMBLYAI_API_KEY", "api_key"),
        "elevenlabs": ("ELEVENLABS_API_KEY", "api_key"),
    }
    
    # Try environment variables first (for Docker)
    for service, (env_var, key_name) in env_mappings.items():
        value = os.getenv(env_var)
        if value:
            secrets[service] = {key_name: value}
            logger.info(f"Loaded {service} key from environment")
    
    # Load from database (CLI-managed keys)
    db_secrets = load_secrets_from_db()
    # Environment variables take precedence
    for service, key_data in db_secrets.items():
        if service not in secrets:
            secrets[service] = key_data
    
    if not secrets:
        logger.warning("No secrets loaded. Proxy will not authenticate requests.")
    
    return secrets


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
    "azure_openai": "https://{resource}.openai.azure.com/openai",
    "aws_bedrock": "https://bedrock-runtime.{region}.amazonaws.com",
    
    # Vector Databases
    "pinecone": "https://api.pinecone.io",
    "weaviate": "https://{cluster}.weaviate.network",
    "qdrant": "https://{cluster}.cloud.qdrant.io",
    "chroma": "http://localhost:8000",
    "milvus": "https://{cluster}.milvus.io",
    
    # Search & Data
    "brave": "https://api.search.brave.com",
    "serpapi": "https://serpapi.com",
    "tavily": "https://api.tavily.com",
    "exa": "https://api.exa.ai",
    "perplexity": "https://api.perplexity.ai",
    
    # Git & Dev
    "github": "https://api.github.com",
    "gitlab": "https://gitlab.com/api/v4",
    "bitbucket": "https://api.bitbucket.org/2.0",
    
    # Cloud & Storage
    "aws": "https://sts.amazonaws.com",
    "supabase": "https://{project}.supabase.co",
    "firebase": "https://firebase.googleapis.com",
    
    # Communication
    "slack": "https://slack.com/api",
    "discord": "https://discord.com/api/v10",
    "telegram": "https://api.telegram.org",
    "twilio": "https://api.twilio.com/2010-04-01",
    "sendgrid": "https://api.sendgrid.com/v3",
    
    # Monitoring & Analytics
    "langsmith": "https://api.smith.langchain.com",
    "langfuse": "https://cloud.langfuse.com/api/public",
    "weights_biases": "https://api.wandb.ai",
    "arize": "https://api.arize.com",
    
    # Image & Media
    "replicate": "https://api.replicate.com/v1",
    "stability": "https://api.stability.ai/v2beta",
    "cloudinary": "https://api.cloudinary.com/v1_1",
    
    # Other AI Services
    "huggingface": "https://api-inference.huggingface.co",
    "assemblyai": "https://api.assemblyai.com/v2",
    "elevenlabs": "https://api.elevenlabs.io/v1",
}


def get_auth_header(service: str) -> Optional[str]:
    """Get the Authorization header value for a service."""
    if service not in _secrets:
        return None
    
    # Bearer token services
    bearer_services = [
        "openrouter", "openai", "anthropic", "gemini", "groq",
        "cohere", "mistral", "deepseek", "azure_openai",
        "pinecone", "weaviate", "qdrant", "chroma", "milvus",
        "brave", "serpapi", "tavily", "exa", "perplexity",
        "gitlab", "bitbucket", "supabase", "firebase",
        "langsmith", "langfuse", "weights_biases", "arize",
        "stability", "cloudinary", "assemblyai", "elevenlabs",
    ]
    
    if service in bearer_services:
        return f"Bearer {_secrets[service]['api_key']}"
    elif service == "github":
        return f"token {_secrets[service]['pat']}"
    elif service in ["slack", "discord"]:
        return f"Bearer {_secrets[service]['token']}"
    elif service == "telegram":
        return None  # Telegram uses token in URL
    elif service == "twilio":
        import base64
        account_sid = _secrets[service].get('account_sid', '')
        token = _secrets[service]['token']
        credentials = base64.b64encode(f"{account_sid}:{token}".encode()).decode()
        return f"Basic {credentials}"
    elif service == "sendgrid":
        return f"Bearer {_secrets[service]['api_key']}"
    elif service == "replicate":
        return f"Token {_secrets[service]['token']}"
    elif service == "huggingface":
        return f"Bearer {_secrets[service]['token']}"
    
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
    version="0.9.0-beta",
    lifespan=lifespan,
)

# Add security middleware
app.add_middleware(SecurityMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware, requests_per_minute=60, burst_size=10)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
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
    
    # Handle dynamic URLs
    if service == "azure_openai" and "resource" in _secrets.get(service, {}):
        resource = _secrets[service]["resource"]
        target_base = f"https://{resource}.openai.azure.com/openai"
    elif service == "weaviate" and "cluster" in _secrets.get(service, {}):
        cluster = _secrets[service]["cluster"]
        target_base = f"https://{cluster}.weaviate.network"
    elif service == "qdrant" and "cluster" in _secrets.get(service, {}):
        cluster = _secrets[service]["cluster"]
        target_base = f"https://{cluster}.cloud.qdrant.io"
    elif service == "milvus" and "cluster" in _secrets.get(service, {}):
        cluster = _secrets[service]["cluster"]
        target_base = f"https://{cluster}.milvus.io"
    elif service == "supabase" and "project" in _secrets.get(service, {}):
        project = _secrets[service]["project"]
        target_base = f"https://{project}.supabase.co"
    elif service == "cloudinary" and "cloud_name" in _secrets.get(service, {}):
        cloud_name = _secrets[service]["cloud_name"]
        target_base = f"https://api.cloudinary.com/v1_1/{cloud_name}"
    
    target_url = f"{target_base}/{path}"
    
    # Handle service-specific URL modifications
    if service == "gemini" and "api_key" in _secrets.get(service, {}):
        query_params = {**query_params, "key": _secrets[service]["api_key"]}
    elif service == "telegram" and "token" in _secrets.get(service, {}):
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
    }
    
    if service in header_overrides:
        forward_headers.update(header_overrides[service])
    
    # Add Accept: application/json for most services
    if service not in ["gemini", "telegram"]:
        forward_headers.setdefault("Accept", "application/json")
    
    logger.info(f"Proxying {method} {target_url}")
    
    # Make request with retry logic
    max_retries = 3
    retry_delay = 1.0
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        for attempt in range(max_retries):
            try:
                response = await client.request(
                    method=method,
                    url=target_url,
                    headers=forward_headers,
                    content=body,
                    follow_redirects=True
                )
                
                logger.info(f"Response: {response.status_code}")
                
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers)
                )
                
            except httpx.TimeoutException:
                if attempt < max_retries - 1:
                    logger.warning(f"Timeout on attempt {attempt + 1}, retrying...")
                    await asyncio.sleep(retry_delay * (attempt + 1))
                    continue
                logger.error(f"Timeout proxying to {service} after {max_retries} attempts")
                raise HTTPException(status_code=504, detail="Gateway timeout")
                
            except httpx.ConnectError as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Connection error on attempt {attempt + 1}, retrying...")
                    await asyncio.sleep(retry_delay * (attempt + 1))
                    continue
                logger.error(f"Connection error after {max_retries} attempts: {e}")
                raise HTTPException(status_code=502, detail="Bad gateway")
                
            except httpx.HTTPStatusError as e:
                # Don't retry 4xx errors
                if e.response.status_code < 500:
                    raise HTTPException(
                        status_code=e.response.status_code,
                        detail=f"Upstream error: {e.response.text}"
                    )
                if attempt < max_retries - 1:
                    logger.warning(f"HTTP error {e.response.status_code} on attempt {attempt + 1}, retrying...")
                    await asyncio.sleep(retry_delay * (attempt + 1))
                    continue
                raise HTTPException(
                    status_code=e.response.status_code,
                    detail=f"Upstream error after retries: {e.response.text}"
                )
                
            except Exception as e:
                logger.error(f"Unexpected error proxying to {service}: {e}")
                raise HTTPException(status_code=500, detail=f"Internal proxy error: {str(e)}")


@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_endpoint(request: Request, service: str, path: str):
    """Main proxy endpoint for all services."""
    
    body = await request.body()
    query_params = dict(request.query_params)
    
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
    """Health check endpoint with detailed status."""
    import time
    
    # Check database connectivity
    db_status = "healthy"
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        conn.close()
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    # Get memory usage
    try:
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
    except ImportError:
        memory_mb = None
    
    return {
        "status": "healthy",
        "version": "0.9.0-beta",
        "timestamp": time.time(),
        "services": {
            "available": len(TARGETS),
            "configured": len(_secrets),
            "configured_list": list(_secrets.keys())
        },
        "database": db_status,
        "memory_mb": memory_mb,
        "features": {
            "rate_limiting": True,
            "cors": True,
            "retry_logic": True,
            "security_headers": True
        }
    }


@app.get("/")
async def root():
    """Root endpoint with usage info."""
    return {
        "name": "Agent Vault Proxy",
        "version": "0.9.0-beta",
        "description": "Secure API Key Injection Proxy for 30+ AI Services",
        "services": {
            "openrouter": "OpenRouter (unified LLM access)",
            "openai": "OpenAI (GPT-4, etc.)",
            "anthropic": "Anthropic (Claude)",
            "gemini": "Google Gemini",
            "groq": "Groq (fast inference)",
            "cohere": "Cohere",
            "mistral": "Mistral AI",
            "deepseek": "DeepSeek",
            "pinecone": "Pinecone Vector DB",
            "brave": "Brave Search",
            "github": "GitHub API",
            "slack": "Slack API",
            "langsmith": "LangSmith (LLM tracing)",
        },
        "usage": "POST/GET /{service}/{api-path} - Auth headers injected automatically",
        "cli": "./cli.py - Manage keys and configuration",
        "health": "/health - Check configured services",
        "docs": "/docs - OpenAPI documentation"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
