# KeyRelay v2.0.0

Sicherer API-Key-Proxy fuer Agenten und Tools.  
KeyRelay injiziert echte API-Keys serverseitig, waehrend Clients nur mit Proxy-Endpunkten arbeiten.

## Status

- Version: `2.0.0`
- Teststatus: `102/102` gruen
- Architektur: einheitliche `main.py`, kein paralleler v1/v2-Stack mehr

## Was KeyRelay loest

- Keine echten Provider-Keys im Agent-Code
- Zentrale Verwaltung, Rotation und Audit von API-Zugriffen
- Einheitlicher Proxy fuer viele externe Services
- RBAC fuer Proxy-Zugriff (`user`/`admin`)

## Sicherheitsmodell

- Verschluesselter Vault in SQLite (Fernet)
- Request-Audit-Logging in SQLite
- Rate-Limiting, Security-Middleware und CORS
- Optionaler Agent-Auth-Zwang per `REQUIRE_AGENT_AUTH`

## Auth-Modi

### Produktion (Standard)

- `REQUIRE_AGENT_AUTH=true` (Default)
- Jeder Proxy-Request braucht `Authorization: Bearer <proxy_user_api_key>`
- API-Keys fuer Zielservices liegen im Vault

### Lokale Entwicklung

- `REQUIRE_AGENT_AUTH=false`
- Kein Proxy-User-Token fuer Requests erforderlich
- Sinnvoll fuer lokale Tests und schnellen Start

## Quick Start (Docker)

### 1) Repo klonen

```bash
git clone https://github.com/CodingFlexx/keyrelay.git
cd keyrelay
```

### 2) Encryption Key setzen

```bash
export AGENT_VAULT_KEY="$(python3 - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
)"
```

### 3) Container starten

```bash
docker-compose up -d
```

### 4) Vault initialisieren und Schluessel hinterlegen

```bash
python3 cli.py init
python3 cli.py add-key --service openai
```

### 5) Optional: Proxy-User anlegen (Production-Modus)

```bash
python3 cli.py user-create my-agent --role user --password 'change-me'
```

Die CLI zeigt den API-Key fuer den User einmalig an.

## Docker-Persistenz

`docker-compose.yml` mountet `./data` nach `/app/data`.  
Damit bleiben `vault.db`, User und Audit-Logs bei Neustarts erhalten.

## Beispiel-Request

```bash
curl -X POST "http://localhost:8080/openai/chat/completions" \
  -H "Authorization: Bearer <proxy-user-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role":"user","content":"Hi"}]
  }'
```

Fuer lokale Entwicklung mit `REQUIRE_AGENT_AUTH=false` kann der Authorization-Header entfallen.

## Health und Admin-Endpunkte

- `GET /health`
- `GET /health/services`
- `GET /admin/audit-logs` (admin)
- `GET /admin/audit-stats` (admin)
- `GET /admin/services` (admin)

## Tests

```bash
python3 -m pytest tests -q
```

## Dokumentation

- [Remote Setup](docs/REMOTE_SETUP.md)
- [HTTPS/TLS Setup](docs/HTTPS_SETUP.md)
- [Authentication Setup](docs/AUTH_SETUP.md)

## Lizenz

MIT
