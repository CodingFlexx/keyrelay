# Authentication Setup (v0.9.1)

## Uebersicht

Schnellster Einstieg:

```bash
python3 cli.py setup
```

Der Setup-Flow erstellt auf Wunsch direkt einen Agent-User mit passenden Scopes.

KeyRelay kennt zwei Betriebsarten:

- `REQUIRE_AGENT_AUTH=true` (Default): jeder Proxy-Request braucht einen KeyRelay-User-API-Key.
- `REQUIRE_AGENT_AUTH=false`: lokaler Dev-Modus ohne Agent-Authentifizierung (eingeschraenkte Rechte).

Zusatz fuer v0.9.1+:
- Service-Scopes pro User (`--scope`) begrenzen den Zugriff auf erlaubte Upstreams.
- Scope-Presets in `user-create`: `--scope-preset llm|search|git|all`

Bezug zu den Deployment-Szenarien:
- Szenario 1 und 2 verwenden typischerweise `REQUIRE_AGENT_AUTH=true`
- Szenario 3 verwendet immer `REQUIRE_AGENT_AUTH=true`

## Produktion (empfohlen)

### 1) User anlegen

```bash
python3 cli.py user-create agent-prod --role user --password 'change-me' --scope openai --scope anthropic
# oder preset-basiert:
python3 cli.py user-create agent-prod --role user --scope-preset llm --interactive-scopes
```

Der ausgegebene API-Key ist der Bearer-Token fuer den Agenten.
Wenn kein Scope gesetzt wird, gilt `*` (alle Services).

### 2) Request mit Proxy-Token

```bash
curl -X POST "http://localhost:8080/openai/chat/completions" \
  -H "Authorization: Bearer <proxy-user-key>" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

### 3) Admin-Endpunkte

Nur User mit `role=admin` duerfen:

- `GET /admin/audit-logs`
- `GET /admin/audit-stats`
- `GET /admin/services`
- `GET /health/services`

## Lokaler Dev-Modus

```bash
export REQUIRE_AGENT_AUTH=false
```

Kein Proxy-User-Token noetig. Der anonyme Benutzer erhaelt die Rolle `user`
(nicht `admin`), d.h. Admin-Endpunkte sind auch lokal geschuetzt.

## Integration mit OpenAI-kompatiblen Clients (OpenClaw, LiteLLM, etc.)

KeyRelay ist als Drop-in-Proxy fuer OpenAI-kompatible Clients nutzbar:

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/openai/v1",
    api_key="<proxy-user-key>",   # KeyRelay Proxy-User-Key
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hallo!"}],
)
```

Fuer Anthropic/Claude-Clients:

```python
import anthropic

client = anthropic.Anthropic(
    base_url="http://localhost:8080/anthropic/v1",
    api_key="<proxy-user-key>",
)
```

Konfiguration in `.env` oder als Umgebungsvariable:

```bash
OPENAI_BASE_URL=http://localhost:8080/openai/v1
OPENAI_API_KEY=<proxy-user-key>
```

## Sicherheits-Hinweise

- `REQUIRE_AGENT_AUTH=true` in allen nicht-lokalen Umgebungen.
- Fuer Klartext-Secret-Ausgaben ist explizit `ALLOW_SECRET_REVEAL=true` noetig.
- Proxy nur hinter HTTPS/TLS exponieren (siehe [HTTPS Setup](HTTPS_SETUP.md)).
- API-Keys regelmaessig rotieren (`cli.py rotate-key`).
- Audit-Logs regelmaessig pruefen (`cli.py audit-logs --stats`).
- CORS-Origins einschraenken via `CORS_ALLOWED_ORIGINS` (komma-separiert).
- `/proc` mit `hidepid=2` mounten, um Env-Variablen vor anderen Prozessen zu schuetzen.
- KeyRelay in einem eigenen Container oder User-Namespace betreiben.
