# Agent Vault Proxy

Secure API Key Injection Proxy for AI Agents and Applications.

## Purpose

This FastAPI application acts as a secure proxy that:
- Stores API keys securely (environment variables or mounted secrets file)
- Injects authentication headers into forwarded requests
- Provides a unified interface for multiple AI services
- Keeps your keys out of application code and repositories

## Supported Services

| Endpoint | Target | Auth Type |
|----------|--------|-----------|
| `/openrouter/*` | openrouter.ai/api/v1/* | Bearer Token |
| `/github/*` | api.github.com/* | PAT (token) |
| `/brave/*` | api.search.brave.com/* | Bearer Token |

## Quick Start

### Using Docker (Recommended)

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/agent-vault-proxy.git
   cd agent-vault-proxy
   ```

2. Create your secrets file:
   ```bash
   cp secrets.json.example secrets.json
   # Edit secrets.json with your API keys
   ```

3. Run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

### Using Environment Variables

```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
export GITHUB_PAT="ghp_..."
export BRAVE_API_KEY="BSA..."

python -m uvicorn main:app --host 0.0.0.0 --port 8080
```

### Using Python Directly

```bash
pip install -r requirements.txt

# Create secrets.json from template
cp secrets.json.example secrets.json
# Edit secrets.json with your keys

python main.py
```

## Configuration

### Option 1: Environment Variables (Docker-friendly)

Set these before running:
- `OPENROUTER_API_KEY` - Your OpenRouter API key
- `GITHUB_PAT` - Your GitHub Personal Access Token
- `BRAVE_API_KEY` - Your Brave Search API key
- `SECRETS_FILE` - Path to secrets.json (default: `./secrets.json`)

### Option 2: secrets.json File

Create a `secrets.json` file:

```json
{
  "openrouter": {
    "api_key": "sk-or-v1-..."
  },
  "github": {
    "pat": "ghp_..."
  },
  "brave": {
    "api_key": "BSA..."
  }
}
```

## Usage

Send requests to the proxy instead of directly to APIs:

```bash
# OpenRouter - Chat Completions
curl http://localhost:8080/openrouter/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "google/gemini-2.5-flash-preview",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# GitHub API - List your repos
curl http://localhost:8080/github/user/repos

# Brave Search - Web search
curl "http://localhost:8080/brave/res/v1/web/search?q=fastapi+tutorial"
```

## Docker Deployment

### Basic

```bash
docker build -t agent-vault-proxy .
docker run -p 8080:8080 \
  -e OPENROUTER_API_KEY=sk-or-v1-... \
  -e GITHUB_PAT=ghp_... \
  agent-vault-proxy
```

### With secrets.json

```bash
docker run -p 8080:8080 \
  -v $(pwd)/secrets.json:/app/secrets.json:ro \
  agent-vault-proxy
```

### Docker Compose

```yaml
version: '3.8'

services:
  agent-vault-proxy:
    build: .
    ports:
      - "8080:8080"
    environment:
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
      - GITHUB_PAT=${GITHUB_PAT}
    restart: unless-stopped
```

## Health Check

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "services": ["openrouter", "github", "brave"],
  "configured": ["openrouter", "github"]
}
```

## Security

- **Never commit `secrets.json`** - it's in `.gitignore`
- **Use environment variables** in production (12-factor app)
- **Mount secrets as read-only** in Docker (`:ro` flag)
- **Non-root user** in Docker container
- **No keys in logs** - only service names are logged

## Adding New Services

Edit `main.py`:

1. Add to `TARGETS` dict:
   ```python
   TARGETS = {
       "openrouter": "https://openrouter.ai/api/v1",
       "github": "https://api.github.com",
       "brave": "https://api.search.brave.com",
       "mynewservice": "https://api.myservice.com",
   }
   ```

2. Add auth logic in `get_auth_header()`:
   ```python
   elif service == "mynewservice":
       return f"Bearer {_secrets[service]['api_key']}"
   ```

3. Add service-specific headers in `proxy_request()` if needed.

## License

MIT License - feel free to use and modify.

## Contributing

Pull requests welcome! Please ensure:
- No secrets in commits
- Tests pass
- Documentation updated
