# Remote Setup Guide

Deploy Agent Vault Proxy on a separate server for centralized key management.

## Architecture

```
┌─────────────┐     HTTPS/TLS      ┌─────────────────┐     ┌─────────────┐
│   Agent     │ ═══════════════════► │  Vault Server   │ ──► │   OpenAI    │
│  (Local)    │    Bearer Token      │  (Remote)       │     │   API       │
│             │ ◄═══════════════════ │  Port 443       │     │             │
└─────────────┘                      └─────────────────┘     └─────────────┘
       │                                    │
       │                                    │
       └────────── VPN/Internet ────────────┘
```

## Server Setup (Remote)

### 1. Install Docker & Docker Compose

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y docker.io docker-compose

# Or use official Docker repo for latest version
```

### 2. Clone & Configure

```bash
git clone https://github.com/CodingFlexx/agent-vault-proxy.git
cd agent-vault-proxy

# Create environment file
cp .env.example .env

# Edit .env
nano .env
```

### 3. Environment Configuration

```env
# Required
AGENT_VAULT_KEY=your-32-byte-encryption-key-here!!

# Optional
VAULT_PORT=8080
LOG_LEVEL=INFO
MAX_REQUEST_SIZE=104857600

# TLS (see HTTPS section below)
TLS_CERT_PATH=/certs/cert.pem
TLS_KEY_PATH=/certs/key.pem
```

### 4. Start Services

```bash
# Production mode
docker-compose -f docker-compose.yml up -d

# With TLS (recommended)
docker-compose -f docker-compose.yml -f docker-compose.tls.yml up -d
```

## Agent Configuration (Local)

### Option 1: Environment Variables

```bash
export AGENT_VAULT_URL=https://vault.yourdomain.com
export AGENT_VAULT_TOKEN=your-agent-auth-token
```

### Option 2: Config File

Create `~/.agent-vault/config.json`:

```json
{
  "vault_url": "https://vault.yourdomain.com",
  "vault_token": "your-agent-auth-token",
  "verify_ssl": true
}
```

### Option 3: OpenClaw Integration

In your OpenClaw `.env`:

```env
OPENAI_API_KEY=dummy-key-replaced-by-vault
OPENAI_BASE_URL=https://vault.yourdomain.com/openai
```

## Security Checklist

- [ ] HTTPS/TLS enabled
- [ ] Firewall: Only port 443 open
- [ ] VPN or private network preferred
- [ ] Strong AGENT_VAULT_KEY (32+ bytes)
- [ ] Agent authentication tokens configured
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] Regular backups of SQLite vault

## Troubleshooting

### Connection Refused
```bash
# Check if vault is running
curl https://vault.yourdomain.com/health

# Check firewall
sudo ufw status
```

### TLS Errors
```bash
# Test with curl
curl -v https://vault.yourdomain.com/health

# Check certificate
openssl s_client -connect vault.yourdomain.com:443
```

## Next Steps

See [HTTPS_SETUP.md](HTTPS_SETUP.md) for TLS configuration.
See [AUTH_SETUP.md](AUTH_SETUP.md) for agent authentication.
