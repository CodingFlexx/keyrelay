# Agent Authentication Setup

Secure communication between agents and the vault proxy.

## Overview

```
┌─────────┐                    ┌─────────┐
│  Agent  │ ── Bearer Token ──►│  Vault  │
│         │◄── API Response ───│         │
└─────────┘                    └─────────┘
```

## Authentication Methods

### Method 1: Bearer Token (Recommended)

#### Server Configuration

Add to `main.py`:

```python
from fastapi import Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    if token not in VALID_TOKENS:
        raise HTTPException(status_code=401, detail="Invalid token")
    return token

# Protect routes
@app.get("/{service}/{path:path}", dependencies=[Security(verify_token)])
async def proxy_request(...)
```

#### Token Management

```python
# tokens.py
import secrets
from datetime import datetime, timedelta

class TokenManager:
    def __init__(self, db: Database):
        self.db = db
    
    def create_token(self, agent_id: str, expires_days: int = 30) -> str:
        """Create new agent token."""
        token = f"av_{secrets.token_urlsafe(32)}"
        expires = datetime.utcnow() + timedelta(days=expires_days)
        
        self.db.execute(
            "INSERT INTO tokens (token, agent_id, expires_at) VALUES (?, ?, ?)",
            (token, agent_id, expires)
        )
        return token
    
    def validate_token(self, token: str) -> bool:
        """Check if token is valid and not expired."""
        result = self.db.execute(
            "SELECT expires_at FROM tokens WHERE token = ? AND revoked = 0",
            (token,)
        ).fetchone()
        
        if not result:
            return False
        
        expires = datetime.fromisoformat(result[0])
        return datetime.utcnow() < expires
    
    def revoke_token(self, token: str):
        """Revoke an agent token."""
        self.db.execute(
            "UPDATE tokens SET revoked = 1 WHERE token = ?",
            (token,)
        )
```

#### CLI Commands

Add to `cli.py`:

```python
@app.command()
def create_token(
    agent_id: str = typer.Option(..., help="Unique agent identifier"),
    expires: int = typer.Option(30, help="Token expiry in days")
):
    """Create authentication token for agent."""
    db = get_db()
    manager = TokenManager(db)
    token = manager.create_token(agent_id, expires)
    
    console.print(f"✅ Token created for agent: {agent_id}")
    console.print(f"🔑 Token: {token}")
    console.print(f"⏰ Expires: {expires} days")
    console.print("\n⚠️  Save this token - it won't be shown again!")

@app.command()
def list_tokens():
    """List all active tokens."""
    db = get_db()
    tokens = db.execute(
        "SELECT agent_id, created_at, expires_at FROM tokens WHERE revoked = 0"
    ).fetchall()
    
    table = Table(title="Active Tokens")
    table.add_column("Agent ID", style="cyan")
    table.add_column("Created", style="green")
    table.add_column("Expires", style="yellow")
    
    for token in tokens:
        table.add_row(token[0], token[1], token[2])
    
    console.print(table)

@app.command()
def revoke_token(token: str = typer.Option(..., help="Token to revoke")):
    """Revoke an agent token."""
    db = get_db()
    manager = TokenManager(db)
    manager.revoke_token(token)
    console.print("✅ Token revoked successfully")
```

### Method 2: Mutual TLS (mTLS)

For highest security, use client certificates.

#### Generate Client Certificate

```bash
# Create client key
openssl genrsa -out client-key.pem 2048

# Create CSR
openssl req -new -key client-key.pem -out client.csr \
  -subj "/CN=agent-001/O=YourOrg"

# Sign with CA
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -out client-cert.pem -days 365 -CAcreateserial
```

#### Server Configuration

```python
from fastapi import Request, HTTPException
import ssl

class MTLSVerifier:
    def __init__(self, ca_cert: str):
        self.ca_cert = ca_cert
    
    async def verify(self, request: Request):
        cert = request.scope.get("client_cert")
        if not cert:
            raise HTTPException(status_code=401, detail="Client certificate required")
        
        # Verify certificate chain
        # ... validation logic ...
        
        return cert

# Add to FastAPI
app.add_middleware(MTLSMiddleware, ca_cert="/certs/ca.pem")
```

## Agent Configuration

### Python Client

```python
# agent_client.py
import httpx
from typing import Optional

class VaultClient:
    def __init__(self, vault_url: str, token: str):
        self.vault_url = vault_url.rstrip("/")
        self.token = token
        self.client = httpx.Client(
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0
        )
    
    def chat_completion(self, model: str, messages: list) -> dict:
        """Call OpenAI through vault."""
        response = self.client.post(
            f"{self.vault_url}/openai/chat/completions",
            json={"model": model, "messages": messages}
        )
        response.raise_for_status()
        return response.json()
    
    def health_check(self) -> bool:
        """Check vault health."""
        try:
            response = self.client.get(f"{self.vault_url}/health")
            return response.status_code == 200
        except:
            return False

# Usage
client = VaultClient(
    vault_url="https://vault.yourdomain.com",
    token="av_your_token_here"
)

result = client.chat_completion(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)
```

### OpenClaw Integration

```python
# In your OpenClaw agent
import os
from agent_vault_client import VaultClient

# Initialize with env vars
vault = VaultClient(
    vault_url=os.getenv("AGENT_VAULT_URL"),
    token=os.getenv("AGENT_VAULT_TOKEN")
)

# Use instead of direct API calls
response = vault.chat_completion(
    model="gpt-4",
    messages=conversation
)
```

## Database Schema

```sql
-- Add to schema.sql
CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    agent_id TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT 0,
    last_used TIMESTAMP
);

CREATE INDEX idx_token ON tokens(token);
CREATE INDEX idx_agent ON tokens(agent_id);
```

## Security Best Practices

1. **Token Rotation**: Rotate tokens every 30-90 days
2. **Least Privilege**: One token per agent, minimal permissions
3. **Audit Logging**: Log all token usage
4. **Revocation**: Immediate revocation on compromise
5. **Secure Storage**: Never commit tokens to git
6. **HTTPS Only**: Never use tokens over HTTP

## Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Check token validity and expiry |
| Token not working | Verify Authorization header format |
| Rate limited | Check token-specific rate limits |
| Certificate error | Verify CA trust chain |
