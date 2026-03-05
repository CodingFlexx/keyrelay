# Authentication Setup (v2.0.0)

## Uebersicht

KeyRelay kennt zwei Betriebsarten:

- `REQUIRE_AGENT_AUTH=true` (Default): jeder Proxy-Request braucht einen KeyRelay-User-API-Key.
- `REQUIRE_AGENT_AUTH=false`: lokaler Dev-Modus ohne Agent-Authentifizierung.

## Produktion (empfohlen)

### 1) User anlegen

```bash
python3 cli.py user-create agent-prod --role user --password 'change-me'
```

Der ausgegebene API-Key ist der Bearer-Token fuer den Agenten.

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

## Lokaler Dev-Modus (Dummy-Key-Flow)

```bash
export REQUIRE_AGENT_AUTH=false
```

Dann ist kein Proxy-User-Token mehr notwendig.  
Der Agent kann weiterhin mit einem Dummy-Key arbeiten, solange der eigentliche Provider-Key im KeyRelay-Vault liegt.

## Sicherheits-Hinweise

- `REQUIRE_AGENT_AUTH=true` in allen nicht-lokalen Umgebungen.
- Proxy nur hinter HTTPS/TLS exponieren.
- API-Keys regelmaessig rotieren (`cli.py rotate-key`).
- Audit-Logs regelmaessig pruefen.
