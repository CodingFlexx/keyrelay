import os
import time
from typing import Any, Dict

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.db.database import decrypt_json_value, verify_api_key
from app.core.security import env_bool

security = HTTPBearer(auto_error=False)


async def verify_proxy_access(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> Dict[str, Any]:
    """Verify access token unless explicitly disabled."""
    require_auth = env_bool("REQUIRE_AGENT_AUTH", True)
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

    try:
        session_data = decrypt_json_value(credentials.credentials)
        if session_data.get("type") == "session":
            if time.time() > session_data.get("exp", 0):
                raise HTTPException(status_code=401, detail="Session expired")
            return {
                "username": session_data["username"],
                "role": session_data["role"],
                "scopes": ["*"] if session_data["role"] == "admin" else []
            }
    except Exception:
        pass

    user = verify_api_key(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user
