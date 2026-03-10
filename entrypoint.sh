#!/bin/sh
set -eu

APP_DIR="${AGENT_VAULT_APP_DIR:-/app/data}"
DB_PATH="${APP_DIR}/vault.db"
KEY_FILE="${AGENT_VAULT_KEY_FILE:-${APP_DIR}/.vault_key}"

export AGENT_VAULT_KEY_FILE="${KEY_FILE}"

echo "[keyrelay] startup: checking vault key at ${KEY_FILE}"
if [ ! -f "${KEY_FILE}" ] && [ -z "${AGENT_VAULT_KEY:-}" ]; then
  echo "[keyrelay] vault key not found - generating new one at ${KEY_FILE}"
  python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > "${KEY_FILE}"
  chmod 600 "${KEY_FILE}"
fi

echo "[keyrelay] startup: checking vault at ${DB_PATH}"

if [ ! -f "${DB_PATH}" ]; then
  echo "[keyrelay] vault database not found - initializing"
  python3 - <<'PY'
import database
database.init_database()
print("[keyrelay] init_database completed")
PY
fi

BOOTSTRAP_ADMIN_USERNAME="${BOOTSTRAP_ADMIN_USERNAME:-}"
BOOTSTRAP_ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-}"
BOOTSTRAP_ADMIN_ROLE="${BOOTSTRAP_ADMIN_ROLE:-admin}"
BOOTSTRAP_ADMIN_SCOPES="${BOOTSTRAP_ADMIN_SCOPES:-*}"
BOOTSTRAP_ADMIN_API_KEY_PATH="${BOOTSTRAP_ADMIN_API_KEY_PATH:-}"

if [ -n "${BOOTSTRAP_ADMIN_USERNAME}" ] && [ -n "${BOOTSTRAP_ADMIN_PASSWORD}" ]; then
  echo "[keyrelay] bootstrap: ensuring admin user '${BOOTSTRAP_ADMIN_USERNAME}' exists"
  python3 - <<'PY'
import os
import database

username = os.environ["BOOTSTRAP_ADMIN_USERNAME"]
password = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
role = os.environ.get("BOOTSTRAP_ADMIN_ROLE", "admin")
scopes_raw = os.environ.get("BOOTSTRAP_ADMIN_SCOPES", "*")
scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
api_key_path = os.environ.get("BOOTSTRAP_ADMIN_API_KEY_PATH", "").strip()

api_key = database.create_user(username, password, role=role, scopes=scopes)
if api_key:
    print(f"[keyrelay] bootstrap: created user '{username}'")
    if api_key_path:
        try:
            with open(api_key_path, "w", encoding="utf-8") as fh:
                fh.write(api_key + "\n")
            print(f"[keyrelay] bootstrap: wrote admin api key to {api_key_path}")
        except Exception as exc:
            print(f"[keyrelay] bootstrap: failed to write admin api key file: {exc}")
else:
    print(f"[keyrelay] bootstrap: user '{username}' already exists or creation failed")
PY
else
  echo "[keyrelay] bootstrap: admin credentials not provided, skipping user bootstrap"
fi

echo "[keyrelay] startup: launching api server"
exec uvicorn main:app --host 0.0.0.0 --port "${AGENT_VAULT_PORT:-8080}"
