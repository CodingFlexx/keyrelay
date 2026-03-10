import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.api.dependencies import verify_proxy_access
from app.core.config import TARGETS
from app.db.database import (
    admin_exists,
    add_api_key,
    create_user,
    delete_user,
    encrypt_json_value,
    get_audit_logs,
    get_audit_stats,
    list_api_keys,
    list_users,
    remove_api_key,
    verify_user,
)

router = APIRouter()

# Locate static dir relative to app module
STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "static"


class LoginRequest(BaseModel):
    username: str
    password: str

class SetupRequest(BaseModel):
    username: str
    password: str

class AddKeyRequest(BaseModel):
    service_name: str
    api_key: str
    metadata: Optional[Dict[str, Any]] = None

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"
    scopes: List[str] = ["*"]


@router.get("/setup-status")
async def admin_setup_status():
    """Check if the system requires first-run setup."""
    return {"needs_setup": not admin_exists()}


@router.post("/setup")
async def admin_setup(req: SetupRequest):
    """First-run setup to create the initial admin user."""
    if admin_exists():
        raise HTTPException(status_code=403, detail="System already initialized")
    
    api_key = create_user(req.username, req.password, role="admin", scopes=["*"])
    if not api_key:
        raise HTTPException(status_code=400, detail="Failed to create admin user")
    
    # Auto-login after setup
    user = verify_user(req.username, req.password)
    session_data = {
        "username": user["username"],
        "role": user["role"],
        "exp": time.time() + 86400,
        "type": "session"
    }
    token = encrypt_json_value(session_data)
    return {"token": token, "user": user}


@router.post("/login")
async def admin_login(req: LoginRequest):
    user = verify_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    session_data = {
        "username": user["username"],
        "role": user["role"],
        "exp": time.time() + 86400,
        "type": "session"
    }
    token = encrypt_json_value(session_data)
    return {"token": token, "user": user}


@router.post("/keys")
async def api_add_key(req: AddKeyRequest, user: Dict[str, Any] = Depends(verify_proxy_access)):
    success = add_api_key(req.service_name, req.api_key, req.metadata)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to add key")
    return {"status": "success", "service": req.service_name}


@router.delete("/keys/{service}")
async def api_remove_key(service: str, user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    success = remove_api_key(service)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "success", "service": service}


@router.post("/users")
async def api_create_user(req: CreateUserRequest, user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    api_key = create_user(req.username, req.password, req.role, req.scopes)
    if not api_key:
        raise HTTPException(status_code=400, detail="Failed to create user (might already exist)")
    return {
        "status": "success",
        "username": req.username,
        "api_key": api_key if req.role != "admin" else None
    }


@router.delete("/users/{username}")
async def api_delete_user(username: str, user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    success = delete_user(username)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "success", "username": username}


@router.get("/audit-logs")
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


@router.get("/audit-stats")
async def admin_audit_stats(user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_audit_stats()


@router.get("/services")
async def admin_services(user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"services": list(TARGETS.keys()), "count": len(TARGETS)}


@router.get("/users")
async def admin_users(user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    users = list_users()
    return {"users": users, "count": len(users)}


@router.get("/keys")
async def admin_keys(user: Dict[str, Any] = Depends(verify_proxy_access)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    keys = list_api_keys()
    return {"keys": keys, "count": len(keys)}


@router.get("/ui")
async def admin_ui():
    ui_file = STATIC_DIR / "admin_ui.html"
    if not ui_file.exists():
        raise HTTPException(status_code=404, detail="Admin UI not available")
    return FileResponse(str(ui_file))
