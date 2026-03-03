# Agent Vault Proxy

Secure API Key Injection Proxy for AI Agents and Applications.

## Purpose

This FastAPI application acts as a secure proxy that:
- Stores API keys securely (environment variables or mounted secrets file)
- Injects authentication headers into forwarded requests
- Provides a unified interface for 30+ AI services
- Keeps your keys out of application code and repositories

**How it works:**
1. AI Agents use a dummy/fictitious API key
2. Request goes to the proxy
3. Proxy injects the real API key
4. Response returns directly to the agent
5. **Keys are never exposed to agents!**

## Supported Services (30+)

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
| `/azure_openai/*` | Azure OpenAI | Bearer |
| `/aws_bedrock/*` | AWS Bedrock | AWS SigV4 |

### Vector Databases
| Endpoint | Service | Auth |
|----------|---------|------|
| `/pinecone/*` | Pinecone | Bearer |
| `/weaviate/*` | Weaviate | Bearer |
| `/qdrant/*` | Qdrant | Bearer |
| `/chroma/*` | Chroma | Bearer |
| `/milvus/*` | Milvus | Bearer |

### Search APIs
| Endpoint | Service | Auth |
|----------|---------|------|
| `/brave/*` | Brave Search | Bearer |
| `/serpapi/*` | SerpAPI (Google Search) | Bearer |
| `/tavily/*` | Tavily (AI search) | Bearer |
| `/exa/*` | Exa AI Search | Bearer |
| `/perplexity/*` | Perplexity API | Bearer |

### Git & Dev
| Endpoint | Service | Auth |
|----------|---------|------|
| `/github/*` | GitHub API | Token |
| `/gitlab/*` | GitLab API | Bearer |
| `/bitbucket/*` | Bitbucket API | Bearer |

### Cloud & Storage
| Endpoint | Service | Auth |
|----------|---------|------|
| `/supabase/*` | Supabase | Bearer |
| `/firebase/*` | Firebase | Token |

### Communication
| Endpoint | Service | Auth |
|----------|---------|------|
| `/slack/*` | Slack API | Bearer |
| `/discord/*` | Discord API | Bot Token |
| `/telegram/*` | Telegram Bot API | Token (URL) |
| `/twilio/*` | Twilio | Basic Auth |
| `/sendgrid/*` | SendGrid | Bearer |

### Monitoring & Analytics
| Endpoint | Service | Auth |
|----------|---------|------|
| `/langsmith/*` | LangSmith (LLM tracing) | Bearer |
| `/langfuse/*` | Langfuse | Bearer |
| `/weights_biases/*` | Weights & Biases | Bearer |
| `/arize/*` | Arize AI | Bearer |

### Image & Media
| Endpoint | Service | Auth |
|----------|---------|------|
| `/replicate/*` | Replicate | Token |
| `/stability/*` | Stability AI | Bearer |
| `/cloudinary/*` | Cloudinary | API Key |

### Other AI Services
| Endpoint | Service | Auth |
|----------|---------|------|
| `/huggingface/*` | Hugging Face | Bearer |
| `/assemblyai/*` | AssemblyAI | Bearer |
| `/elevenlabs/*` | ElevenLabs | Bearer |

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

**LLM APIs:**
- `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- `GEMINI_API_KEY`, `GROQ_API_KEY`, `COHERE_API_KEY`
- `MISTRAL_API_KEY`, `DEEPSEEK_API_KEY`
- `AZURE_OPENAI_API_KEY`, `AWS_BEDROCK_KEY`

**Vector Databases:**
- `PINECONE_API_KEY`, `WEAVIATE_API_KEY`, `QDRANT_API_KEY`
- `CHROMA_API_KEY`, `MILVUS_API_KEY`

**Search APIs:**
- `BRAVE_API_KEY`, `SERPAPI_KEY`, `TAVILY_API_KEY`
- `EXA_API_KEY`, `PERPLEXITY_API_KEY`

**Git APIs:**
- `GITHUB_PAT`, `GITLAB_TOKEN`, `BITBUCKET_TOKEN`

**Cloud:**
- `SUPABASE_KEY`, `FIREBASE_TOKEN`

**Communication:**
- `SLACK_TOKEN`, `DISCORD_TOKEN`, `TELEGRAM_BOT_TOKEN`
- `TWILIO_AUTH_TOKEN`, `SENDGRID_API_KEY`

**Monitoring:**
- `LANGSMITH_API_KEY`, `LANGFUSE_PUBLIC_KEY`
- `WANDB_API_KEY`, `ARIZE_API_KEY`

**Image & Media:**
- `REPLICATE_API_TOKEN`, `STABILITY_API_KEY`, `CLOUDINARY_API_KEY`

**Other AI:**
- `HF_API_TOKEN`, `ASSEMBLYAI_API_KEY`, `ELEVENLABS_API_KEY`

**General:**
- `SECRETS_FILE` - Path to secrets.json (default: `./secrets.json`)

### Option 2: secrets.json File

Create a `secrets.json` file (see `secrets.json.example` for all services).

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

### Vector Databases

```bash
# Pinecone - List indexes
curl http://localhost:8080/pinecone/indexes

# Weaviate - Query
curl http://localhost:8080/weaviate/v1/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ Get { Article { title } } }"}'

# Qdrant - Search
curl http://localhost:8080/qdrant/collections/my_collection/points/search \
  -H "Content-Type: application/json" \
  -d '{"vector": [0.1, 0.2, 0.3], "limit": 10}'
```

### Search APIs

```bash
# Brave Search
curl "http://localhost:8080/brave/res/v1/web/search?q=fastapi+tutorial"

# Tavily
curl http://localhost:8080/tavily/search \
  -H "Content-Type: application/json" \
  -d '{"query": "latest AI news", "max_results": 5}'

# Perplexity
curl http://localhost:8080/perplexity/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "sonar", "messages": [{"role": "user", "content": "What is AI?"}]}'
```

### Git & Dev

```bash
# GitHub - List repos
curl http://localhost:8080/github/user/repos

# GitLab - List projects
curl http://localhost:8080/gitlab/projects

# Bitbucket - List repos
curl http://localhost:8080/bitbucket/repositories/{workspace}
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

# Twilio - Send SMS
curl http://localhost:8080/twilio/Accounts/{account_sid}/Messages.json \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'To=+1234567890&From=+0987654321&Body=Hello'
```

### Image & Media

```bash
# Replicate - Run model
curl http://localhost:8080/replicate/models/stability-ai/stable-diffusion/predictions \
  -H "Content-Type: application/json" \
  -d '{"input": {"prompt": "a photo of an astronaut riding a horse"}}'

# Stability AI - Generate image
curl http://localhost:8080/stability/generation/stable-diffusion-v1-6/text-to-image \
  -H "Content-Type: application/json" \
  -d '{"text_prompts": [{"text": "a photo of an astronaut"}]}'

# ElevenLabs - Text to speech
curl http://localhost:8080/elevenlabs/text-to-speech/21m00Tcm4TlvDq8ikWAM \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello from Agent Vault!"}'
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
      - PINECONE_API_KEY=${PINECONE_API_KEY}
    restart: unless-stopped
```

### Integration with OpenClaw/Nanobot

```yaml
version: '3.8'

services:
  # The secure proxy
  agent-vault-proxy:
    image: agent-vault-proxy:latest
    environment:
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - PINECONE_API_KEY=${PINECONE_API_KEY}
    networks:
      - agent-network

  # AI Agent - no real keys needed!
  openclaw:
    image: openclaw:latest
    environment:
      # Dummy keys - proxy handles the real ones
      - OPENROUTER_API_KEY=dummy-key
      - ANTHROPIC_API_KEY=dummy-key
      # Point to proxy instead of real APIs
      - OPENROUTER_BASE_URL=http://agent-vault-proxy:8080/openrouter
      - ANTHROPIC_BASE_URL=http://agent-vault-proxy:8080/anthropic
      - PINECONE_BASE_URL=http://agent-vault-proxy:8080/pinecone
    networks:
      - agent-network
    depends_on:
      - agent-vault-proxy

networks:
  agent-network:
    driver: bridge
```

## Health Check

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "services": ["openrouter", "github", "brave", "pinecone"],
  "configured": ["openrouter", "github"]
}
```

## Security

- **Never commit `secrets.json`** - it's in `.gitignore`
- **Use environment variables** in production (12-factor app)
- **Mount secrets as read-only** in Docker (`:ro` flag)
- **Non-root user** in Docker container
- **No keys in logs** - only service names are logged
- **Agents never see real keys** - only dummy keys for proxy routing

### Security Model

The proxy implements a **Key Isolation Pattern**:

1. **Agents** use dummy keys (e.g., `dummy-openrouter-key`)
2. **Proxy** validates the service endpoint, injects real key
3. **Real keys** never leave the secure proxy container
4. **Network isolation** - agents only talk to proxy, not external APIs

This means:
- ✅ Agent code can be open-source without exposing keys
- ✅ Agent containers don't need secret management
- ✅ Keys can be rotated without agent redeployment
- ✅ Compromised agents can't leak real API keys

## Zero-Friction Integration

The proxy is designed as a **transparent drop-in replacement**. AI agents keep their complete configuration (models, parameters, temperature, etc.) - only the API endpoint and a dummy key need to change.

### Before (Direct API Access)
```python
# Agent configuration
OPENROUTER_API_KEY = "sk-or-v1-abc123..."  # ❌ Real key exposed
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Model configuration stays the same
MODEL = "google/gemini-2.5-flash-preview"
TEMPERATURE = 0.7
MAX_TOKENS = 4096
```

### After (Via Proxy)
```python
# Agent configuration - ONLY these change
OPENROUTER_API_KEY = "dummy-openrouter-key"  # ✅ Dummy/fictitious key
OPENROUTER_BASE_URL = "http://proxy:8080/openrouter"  # ✅ Proxy endpoint

# Model configuration stays EXACTLY the same
MODEL = "google/gemini-2.5-flash-preview"
TEMPERATURE = 0.7
MAX_TOKENS = 4096
# ... all other parameters unchanged
```

### OpenClaw/Nanobot Example
```yaml
# config.yaml - ONLY change base_url and use dummy key
llm:
  provider: openrouter
  base_url: http://agent-vault-proxy:8080/openrouter  # ← Proxy endpoint
  api_key: dummy-openrouter-key  # ← Any non-empty string works
  model: google/gemini-2.5-flash-preview
  temperature: 0.7
  max_tokens: 4096
  # All other settings unchanged
```

### Generic Integration Pattern
```python
import os

# Configuration (only these 2 lines change per environment)
API_KEY = os.getenv("API_KEY", "dummy-key")  # Dummy key for proxy
BASE_URL = os.getenv("BASE_URL", "http://localhost:8080/openrouter")

# Everything else stays the same
MODEL = "claude-3-opus-20240229"
TEMPERATURE = 0.7
# ... rest of config

# Client initialization (OpenAI-compatible)
from openai import OpenAI
client = OpenAI(
    api_key=API_KEY,      # Dummy key - proxy replaces it
    base_url=BASE_URL,    # Proxy endpoint
)

# Usage is IDENTICAL to direct API access
response = client.chat.completions.create(
    model=MODEL,
    temperature=TEMPERATURE,
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### Key Points
- ✅ **Zero config changes** for models, parameters, or request format
- ✅ **Same API** - OpenAI-compatible clients work unchanged
- ✅ **Dummy key** can be any string (e.g., `dummy`, `proxy`, `vault`)
- ✅ **Proxy injects** the real key from secure storage
- ✅ **Response flows** directly back to agent

## Architecture

```
┌─────────────┐     Dummy Key      ┌─────────────────┐     Real Key       ┌─────────────┐
│  AI Agent   │ ─────────────────→ │  Agent Vault    │ ─────────────────→ │   OpenAI    │
│  (OpenClaw) │                    │  Proxy          │                    │   API       │
│             │  Model, Params   │                 │                    │             │
│             │  (unchanged)     │                 │                    │             │
└─────────────┘                    └─────────────────┘                    └─────────────┘
       ↑                                    │                                    │
       │                                    │                                    │
       └────────────────────────────────────┴────────────────────────────────────┘
                                    Response
                                    (unchanged)
```

## Adding New Services

Edit `main.py`:

1. Add to `TARGETS` dict:
   ```python
   TARGETS = {
       "openrouter": "https://openrouter.ai/api/v1",
       "mynewservice": "https://api.myservice.com",
   }
   ```

2. Add env mapping in `load_secrets()`:
   ```python
   "mynewservice": ("MYNEW_API_KEY", "api_key"),
   ```

3. Add auth logic in `get_auth_header()`:
   ```python
   elif service == "mynewservice":
       return f"Bearer {_secrets[service]['api_key']}"
   ```

4. Add service-specific headers if needed.

## License

MIT License - feel free to use and modify.

## Contributing

Pull requests welcome! Please ensure:
- No secrets in commits
- Tests pass
- Documentation updated
