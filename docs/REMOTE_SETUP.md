# Remote Setup (v0.9.0)

Dies entspricht dem offiziellen Deployment-Szenario 3:
- Agent lokal oder im Container auf Host A
- KeyRelay auf Host B nur per Netzwerk / HTTPS erreichbar

## Zielbild

KeyRelay laeuft auf einem separaten Host, Agents verbinden sich nur per HTTPS.

```text
Agent -> HTTPS Reverse Proxy -> KeyRelay (Port 8080) -> Ziel-APIs
```

## 1) Server vorbereiten

```bash
mkdir -p keyrelay/secrets
cd keyrelay
```

Empfohlen fuer Docker-Deployments: `examples/docker-compose.remote.yml` verwenden.
Die folgenden Schritte zeigen den direkten Compose-Flow.

## 2) Pflicht-Variablen setzen

```bash
mkdir -p secrets
printf '%s\n' "<fernet-key>" > secrets/agent_vault_key
chmod 600 secrets/agent_vault_key
export AGENT_VAULT_KEY_FILE=/run/secrets/agent_vault_key
export KEYRELAY_SECURITY_MODE=remote_secure
export REQUIRE_AGENT_AUTH=true
```

Der Vault-Key muss dauerhaft stabil sein, sonst koennen bestehende Keys nicht mehr entschluesselt werden.

## 3) Bootstrap-Admin setzen

```bash
export BOOTSTRAP_ADMIN_USERNAME=admin
export BOOTSTRAP_ADMIN_PASSWORD='<starkes-passwort>'
export BOOTSTRAP_ADMIN_SCOPES='*'
```

## 4) Starten

```bash
docker compose -f examples/docker-compose.remote.yml up -d
```

Beim ersten Start werden DB und Bootstrap-User automatisch erstellt.

## 5) Admin-UI und Agent anbinden

- Admin-UI hinter deinem TLS-Host oeffnen (z. B. `https://keyrelay.example.com/admin/ui`)
- per Admin-Token Service-Keys und Proxy-User anlegen
- alternativ fuer Terminal-Only weiterhin `python3 cli.py setup` nutzen

```bash
curl -X POST "https://vault.example.com/openai/chat/completions" \
  -H "Authorization: Bearer <proxy-user-key>" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

## Betriebshinweise

- Datenpersistenz liegt unter `./data` (gemountet nach `/app/data`).
- Admin-Audits ueber `/admin/audit-logs` und `/admin/audit-stats`.
- TLS ueber Reverse Proxy, siehe [HTTPS_SETUP.md](HTTPS_SETUP.md).
- Auth-Details siehe [AUTH_SETUP.md](AUTH_SETUP.md).
