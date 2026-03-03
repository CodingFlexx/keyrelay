# Agent Vault Proxy

Secure API Key Injection Proxy for AI Agents.

## Purpose

This FastAPI application acts as a secure proxy that:
- Stores API keys locally in `secrets.json` (never in code/repos)
- Injects authentication headers into forwarded requests
- Provides a unified interface for multiple AI services

## Supported Services

| Endpoint | Target | Auth Type |
|----------|--------|-----------|
| `/openrouter/*` | openrouter.ai/api/v1/* | Bearer Token |
| `/github/*` | api.github.com/* | PAT (token) |
| `/brave/*` | api.search.brave.com/* | Bearer Token |

## Setup

1. Copy `secrets.json.example` to `secrets.json`:
   ```bash
   cp secrets.json.example secrets.json
   ```

2. Add your API keys to `secrets.json`:
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

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the proxy:
   ```bash
   python main.py
   ```

## Usage

Send requests to the proxy instead of directly to APIs:

```bash
# OpenRouter
curl http://localhost:8080/openrouter/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "google/gemini-2.5-flash-preview", "messages": [...]}'

# GitHub API
curl http://localhost:8080/github/user/repos

# Brave Search (prepared)
curl "http://localhost:8080/brave/res/v1/web/search?q=test"
```

## Security

- `secrets.json` is in `.gitignore` - never commit it!
- Keys are loaded at startup and kept in memory
- No keys are logged or exposed in responses

## Deployment

For production, use a proper WSGI server:

```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --workers 4
```

## Health Check

```bash
curl http://localhost:8080/health
```
