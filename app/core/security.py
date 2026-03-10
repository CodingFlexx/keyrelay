import base64
import os
from typing import Any, Dict, Optional

from app.core.config import TARGETS, SERVICE_CONFIGS


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def is_service_allowed(user: Dict[str, Any], service: str) -> bool:
    """Check whether a user may access a given upstream service."""
    if user.get("role") == "admin":
        return True

    scopes = user.get("scopes")
    if not isinstance(scopes, list):
        return True

    normalized_scopes = {str(scope).strip().lower() for scope in scopes if str(scope).strip()}
    if not normalized_scopes or "*" in normalized_scopes:
        return True
    return service.lower() in normalized_scopes


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
