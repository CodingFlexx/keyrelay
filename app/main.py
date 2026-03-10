import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.endpoints import admin, health, proxy
from app.core.config import TARGETS, get_cors_origins
from app.db.database import DB_PATH, init_database
from app.middleware.middleware import LoggingMiddleware, RateLimitMiddleware, SecurityMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


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

STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.add_middleware(SecurityMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware, requests_per_minute=60, burst_size=10)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
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

# Map /agent/keys to the same handler as /admin/keys to preserve backwards compatibility
app.include_router(admin.router, prefix="/agent", tags=["agent"])
app.include_router(admin.router, prefix="/admin", tags=["admin"])
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(proxy.router, tags=["proxy"])

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
