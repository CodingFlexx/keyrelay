# KeyRelay v0.9.1

Sicherer API-Key-Proxy fuer Agenten und Tools.  
KeyRelay injiziert echte API-Keys serverseitig, waehrend Clients nur mit Proxy-Endpunkten arbeiten.

## Status

- Version: `0.9.1`
- Teststatus: `118/118` gruen
- Architektur: einheitliche `main.py`, kein paralleler Legacy-Stack mehr

## Was KeyRelay loest

- Keine echten Provider-Keys im Agent-Code
- Zentrale Verwaltung, Rotation und Audit von API-Zugriffen
- Einheitlicher Proxy fuer viele externe Services
- RBAC fuer Proxy-Zugriff (`user`/`admin`)

## Sicherheitsmodell

- Verschluesselter Vault in SQLite (Fernet AES-128-CBC + HMAC)
- Request-Audit-Logging in SQLite (mit automatischer Rotation)
- Rate-Limiting, Security-Middleware und konfigurierbare CORS
- Agent-Auth-Zwang per `REQUIRE_AGENT_AUTH` (Default: true)
- Dev-Modus (`REQUIRE_AGENT_AUTH=false`) gibt nur `user`-Rolle, kein Admin
- Konfigurierbare CORS-Origins via `CORS_ALLOWED_ORIGINS`

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

## Integration mit OpenAI-kompatiblen Clients

KeyRelay ist als Drop-in-Proxy fuer alle OpenAI-kompatiblen SDKs nutzbar
(OpenClaw, LiteLLM, LangChain, etc.):

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/openai/v1",
    api_key="<proxy-user-key>",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hallo!"}],
)
```

Oder als Umgebungsvariable:

```bash
export OPENAI_BASE_URL=http://localhost:8080/openai/v1
export OPENAI_API_KEY=<proxy-user-key>
```

## Health und Admin-Endpunkte

- `GET /health` - oeffentlich
- `GET /health/services` - erfordert Auth
- `GET /admin/audit-logs` (admin)
- `GET /admin/audit-stats` (admin)
- `GET /admin/services` (admin)

## API-Key-Schutz bei Root-Zugriff

Wenn ein Agent Root-Zugriff auf dem selben System hat, gelten folgende Einschraenkungen:

| Massnahme | Schutzwirkung |
|-----------|--------------|
| Fernet-Verschluesselung im Vault | Entschluesseln erfordert `AGENT_VAULT_KEY` |
| DB-Berechtigungen `0o600` | Nur Owner kann lesen |
| `/proc` mit `hidepid=2` mounten | Env-Vars anderer Prozesse nicht sichtbar |
| Docker/Container-Isolation | Eigener Namespace, kein Host-Zugriff |
| `get-key` mit Bestaetigung | Verhindert versehentliche Klartext-Anzeige |

**Empfehlung**: KeyRelay in einem eigenen Container betreiben und
`AGENT_VAULT_KEY` nur als Docker-Secret uebergeben, nicht als Env-Variable.

```bash
# /proc haerten
sudo mount -o remount,hidepid=2 /proc

# Doctor-Check zeigt Warnungen
python3 cli.py doctor
```

## Tests

```bash
python3 -m pytest tests -q
```

## Umgebungsvariablen

| Variable | Default | Beschreibung |
|----------|---------|-------------|
| `AGENT_VAULT_KEY` | - | Fernet-Schluessel fuer DB-Verschluesselung (erforderlich) |
| `AGENT_VAULT_APP_DIR` | `~/.agent-vault` | Pfad fuer vault.db |
| `REQUIRE_AGENT_AUTH` | `true` | Auth-Zwang fuer Proxy-Requests |
| `CORS_ALLOWED_ORIGINS` | `localhost:3000,localhost:8080` | Erlaubte CORS-Origins |
| `AGENT_VAULT_MAX_AUDIT_ROWS` | `100000` | Maximale Audit-Log-Eintraege |
| `CHROMA_HOST` | `localhost` | Chroma-DB Host |
| `CHROMA_PORT` | `8000` | Chroma-DB Port |

## Dokumentation

- [Remote Setup](docs/REMOTE_SETUP.md)
- [HTTPS/TLS Setup](docs/HTTPS_SETUP.md)
- [Authentication Setup](docs/AUTH_SETUP.md)

## Lizenz

MIT
