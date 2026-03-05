# Remote Setup (v2.0.0)

## Zielbild

KeyRelay laeuft auf einem separaten Host, Agents verbinden sich nur per HTTPS.

```text
Agent -> HTTPS Reverse Proxy -> KeyRelay (Port 8080) -> Ziel-APIs
```

## 1) Server vorbereiten

```bash
git clone https://github.com/CodingFlexx/keyrelay.git
cd keyrelay
mkdir -p data
```

## 2) Pflicht-Variablen setzen

```bash
export AGENT_VAULT_KEY="<fernet-key>"
export REQUIRE_AGENT_AUTH=true
```

`AGENT_VAULT_KEY` muss dauerhaft stabil sein, sonst koennen bestehende Keys nicht mehr entschluesselt werden.

## 3) Starten

```bash
docker-compose up -d
```

## 4) Vault initialisieren und konfigurieren

```bash
python3 cli.py init
python3 cli.py add-key --service openai
python3 cli.py user-create remote-agent --role user --password 'change-me'
```

## 5) Agent anbinden

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
