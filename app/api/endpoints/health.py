from typing import Any, Dict
import httpx
from fastapi import APIRouter, Depends

from app.core.config import TARGETS
from app.db.database import list_api_keys
from app.api.dependencies import verify_proxy_access

router = APIRouter()


@router.get("/")
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


@router.get("/services")
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
