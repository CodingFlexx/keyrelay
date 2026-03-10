# HTTPS/TLS Setup (v0.9.0)

KeyRelay selbst terminiert standardmaessig kein TLS.  
Empfohlen ist ein Reverse Proxy (z. B. Nginx, Caddy, Traefik) vor KeyRelay.

Das ist Pflicht fuer Deployment-Szenario 3 (KeyRelay auf separatem Host im Netzwerk) und optional fuer lokale Szenarien 1 und 2.

## Empfohlene Architektur

```text
Agent -> HTTPS (443) -> Reverse Proxy -> HTTP (8080) -> KeyRelay
```

## Minimal mit Caddy

### `Caddyfile`

```caddy
vault.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Start:

```bash
docker run -d --name caddy \
  -p 80:80 -p 443:443 \
  -v $PWD/Caddyfile:/etc/caddy/Caddyfile \
  -v caddy_data:/data \
  caddy:latest
```

## Minimal mit Nginx

```nginx
server {
    listen 443 ssl;
    server_name vault.example.com;

    ssl_certificate     /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

## Security Checklist

- Nur Port `443` nach aussen oeffnen.
- `REQUIRE_AGENT_AUTH=true` in Produktion.
- `KEYRELAY_SECURITY_MODE=remote_secure` fuer Remote-Deployments setzen.
- Vault-Key als Secret-Datei (`AGENT_VAULT_KEY_FILE`) verwalten, nicht als Klartext-Env.
- Admin-UI (`/admin/ui`) nur intern oder hinter zusaetzlicher Zugriffskontrolle bereitstellen.
- Regelmaessige Zertifikats-Erneuerung sicherstellen.
- Audit-Logs regelmaessig pruefen (`/admin/audit-logs`).
