# Agent Vault Proxy

Secure API Key Injection Proxy for AI Agents and Applications.

## Purpose

This FastAPI application acts as a secure proxy that:
- Stores API keys securely (environment variables or mounted secrets file)
- Injects authentication headers into forwarded requests
- Provides a unified interface for multiple AI services
- Keeps your keys out of application code and repositories

## Supported Services (15+)

### LLM APIs
| Endpoint | Service | Auth |
|----------|---------|------|
| `/openrouter/*` | OpenRouter (unified) | Bearer |
| `/openai/*` | OpenAI (GPT-4, etc.) | Bearer |
| `/anthropic/*` | Anthropic (Claude) | Bearer + Version Header |
| `/gemini/*` | Google Gemini | API Key (Query Param) |
| `/groq/*` | Groq (fast inference) | Bearer |
| `/cohere/*` | Cohere | Bearer |
| `/mistral/*` | Mistral AI | Bearer |
| `/deepseek/*` | DeepSeek | Bearer |

### Search APIs
| Endpoint | Service | Auth |
|----------|---------|------|
| `/brave/*` | Brave Search | Bearer |
| `/serpapi/*` | SerpAPI (Google Search) | Bearer |
| `/tavily/*` | Tavily (AI search) | Bearer |

### Git & Dev
| Endpoint | Service | Auth |
|----------|---------|------|
| `/github/*` | GitHub API | Token |
| `/gitlab/*` | GitLab API | Bearer |

### Communication
| Endpoint | Service | Auth |
|----------|---------|------|
| `/slack/*` | Slack API | Bearer |
| `/discord/*` | Discord API | Bot Token |
| `/telegram/*` | Telegram Bot API | Token (URL) |

### Monitoring
| Endpoint | Service | Auth |
|----------|---------|------|
| `/langsmith/*` | LangSmith (LLM tracing) | Bearer |

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

**LLM APIs:**
- `OPENROUTER_API_KEY` - OpenRouter API key
- `OPENAI_API_KEY` - OpenAI API key
- `ANTHROPIC_API_KEY` - Anthropic API key
- `GEMINI_API_KEY` - Google Gemini API key
- `GROQ_API_KEY` - Groq API key
- `COHERE_API_KEY` - Cohere API key
- `MISTRAL_API_KEY` - Mistral API key
- `DEEPSEEK_API_KEY` - DeepSeek API key

**Search APIs:**
- `BRAVE_API_KEY` - Brave Search API key
- `SERPAPI_KEY` - SerpAPI key
- `TAVILY_API_KEY` - Tavily API key

**Git APIs:**
- `GITHUB_PAT` - GitHub Personal Access Token
- `GITLAB_TOKEN` - GitLab Token

**Communication:**
- `SLACK_TOKEN` - Slack Bot Token
- `DISCORD_TOKEN` - Discord Bot Token
- `TELEGRAM_BOT_TOKEN` - Telegram Bot Token

**Monitoring:**
- `LANGSMITH_API_KEY` - LangSmith API key

**General:**
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

## Usage Examples

### LLM APIs

```bash
# OpenRouter
curl http://localhost:8080/openrouter/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "google/gemini-2.5-flash-preview", "messages": [{"role": "user", "content": "Hello"}]}'

# OpenAI
curl http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}'

# Anthropic (Claude)
curl http://localhost:8080/anthropic/messages \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-3-opus-20240229", "max_tokens": 1024, "messages": [{"role": "user", "content": "Hello"}]}'

# Google Gemini
curl "http://localhost:8080/gemini/models/gemini-pro:generateContent" \
  -H "Content-Type: application/json" \
  -d '{"contents": [{"parts": [{"text": "Hello"}]}]}'

# Groq
curl http://localhost:8080/groq/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3-8b-8192", "messages": [{"role": "user", "content": "Hello"}]}'
```

### Search APIs

```bash
# Brave Search
curl "http://localhost:8080/brave/res/v1/web/search?q=fastapi+tutorial"

# Tavily
curl http://localhost:8080/tavily/search \
  -H "Content-Type: application/json" \
  -d '{"query": "latest AI news", "max_results": 5}'
```

### Git & Dev

```bash
# GitHub - List repos
curl http://localhost:8080/github/user/repos

# GitLab - List projects
curl http://localhost:8080/gitlab/projects
```

### Communication

```bash
# Slack - Post message
curl http://localhost:8080/slack/chat.postMessage \
  -H "Content-Type: application/json" \
  -d '{"channel": "#general", "text": "Hello from Agent Vault!"}'

# Telegram - Send message
curl "http://localhost:8080/telegram/sendMessage?chat_id=123456&text=Hello"

# Discord - Send message
curl http://localhost:8080/discord/channels/123456/messages \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello from Agent Vault!"}'
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
