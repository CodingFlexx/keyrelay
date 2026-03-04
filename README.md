# Agent Vault Proxy v0.9.1

**Secure API Key Management for AI Agents – Zero-Friction Integration**

> **Version:** 0.9.1 (Production Ready)  
> **Tests:** 102/102 passing (100%)  
> **Status:** Feature-complete, ready for v1.0.0

---

## 🎯 What is Agent Vault Proxy?

A **secure proxy** that sits between your AI agents and external APIs. Agents use **dummy keys**, the proxy injects the **real API keys** – without agents ever seeing real keys.

### The Problem
```python
# ❌ BEFORE: API keys in agent code
OPENAI_API_KEY = "sk-abc123..."  # Risk: Leak, Git commit, logs
```

### The Solution
```python
# ✅ AFTER: Only dummy key needed
OPENAI_API_KEY = "dummy-key"  # Proxy replaces with real key
BASE_URL = "http://vault:8080/openai"
```

---

## 🏗️ Two Architecture Options

### Option 1: Local (Same Machine)

```
┌─────────────────────────────────────────┐
│  Host (Your VM/Server)                  │
│  ┌─────────────┐    ┌─────────────────┐ │
│  │  AI Agent   │───►│  Agent Vault    │ │
│  │  (Root)     │    │  (Docker)       │ │
│  │             │◄───│  Port 8080      │ │
│  └─────────────┘    └─────────────────┘ │
│       localhost:8080                    │
└─────────────────────────────────────────┘
```

**When to use:**
- Single agent on dedicated VM
- Quick setup
- Development/Testing

**Benefits:**
- ✅ Simplest setup (docker-compose up)
- ✅ Lowest latency
- ✅ No network configuration

**Security:**
- Agent theoretically has root access to vault possible
- Defense in depth: Encryption, audit logging, container isolation
- For malicious agents: See Option 2

---

### Option 2: Remote (Network-separated)

```
┌─────────────┐      Internet/VPN      ┌─────────────────┐
│   Agent     │  ═══════════════════►  │   Vault Server  │
│  (Local)    │    HTTPS + Auth Token  │  (Remote)       │
│             │  ◄═══════════════════   │  Port 443       │
└─────────────┘                        └─────────────────┘
       │                                      │
       │                                      │
       └─────────────── API Keys ─────────────┘
              (never visible to agent)
```

**When to use:**
- Multiple agents centrally managed
- Highest security requirements
- Production with different agent teams

**Benefits:**
- ✅ Physical separation = Highest security
- ✅ Centralized key management
- ✅ Agents cannot compromise vault
- ✅ Centralized audit logging

**Setup:**
- See [Remote Setup Guide](docs/REMOTE_SETUP.md)
- TLS/HTTPS required
- Bearer token auth

---

## 💡 Why Use Agent Vault Proxy?

| Problem | Solution |
|---------|--------|
| **API keys in Git** | Keys never in code |
| **Keys in logs** | Proxy filters keys out |
| **Rotation overhead** | Rotate centrally, agents untouched |
| **Multi-key chaos** | One vault, 30+ services |
| **No audit trails** | Every request logged |
| **Agent compromise** | Keys stay secure in vault |

### Zero-Friction Integration

**What changes:** Only 2 lines
```python
# BEFORE
client = OpenAI(api_key="sk-real-key...")

# AFTER
client = OpenAI(
    api_key="dummy-key",  # ← Change 1
    base_url="http://vault:8080/openai"  # ← Change 2
)
```

**What stays the same:** Everything else
- Models
- Parameters (temperature, max_tokens)
- Request/Response format
- Error handling
- SDK/Client

---

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/CodingFlexx/agent-vault-proxy.git
cd agent-vault-proxy
```

### 2. Configure

**Option A: CLI (Recommended)**
```bash
python cli.py
# → Select "Setup Vault"
# → Add API keys
```

**Option B: Environment Variables**
```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

**Option C: secrets.json**
```bash
cp secrets.json.example secrets.json
# Edit file
```

### 3. Start
```bash
docker-compose up -d
```

### 4. Test
```bash
curl http://localhost:8080/health
```

---

## 📊 Features

### 🔐 Security
- **Encrypted Vault** - SQLite with Fernet (AES-128-CBC + HMAC)
- **Audit Logging** - Every request with timestamp
- **Rate Limiting** - 60 req/min per IP
- **Circuit Breaker** - Automatic failover
- **Path Traversal Protection** - Blocks `../`, null bytes
- **Request Size Limit** - 100MB max

### 🛠️ Management
- **Interactive CLI** - Typer + Rich UI
- **30+ Services** - LLMs, Vector DBs, Search, Git, Cloud
- **Health Checks** - `/health` and `/health/services`
- **Zero Config** - Docker-ready

### 🔌 Integration
- **OpenAI-compatible** - Works with all OpenAI clients
- **Drop-in Replacement** - Just change base_url
- **Dummy Keys** - Any string works

---

## 📡 Supported Services (30+)

### LLM APIs
| Endpoint | Service | Auth |
|----------|---------|------|
| `/openrouter/*` | OpenRouter (unified) | Bearer |
| `/openai/*` | OpenAI | Bearer |
| `/anthropic/*` | Anthropic (Claude) | Bearer |
| `/gemini/*` | Google Gemini | Query Param |
| `/groq/*` | Groq | Bearer |
| `/cohere/*` | Cohere | Bearer |
| `/mistral/*` | Mistral AI | Bearer |
| `/deepseek/*` | DeepSeek | Bearer |
| `/azure-openai/*` | Azure OpenAI | Bearer |
| `/bedrock/*` | AWS Bedrock | AWS SigV4 |

### Vector Databases
| Endpoint | Service |
|----------|---------|
| `/pinecone/*` | Pinecone |
| `/weaviate/*` | Weaviate |
| `/qdrant/*` | Qdrant |
| `/chroma/*` | Chroma |
| `/milvus/*` | Milvus |

### Search APIs
| Endpoint | Service |
|----------|---------|
| `/brave/*` | Brave Search |
| `/serpapi/*` | SerpAPI |
| `/tavily/*` | Tavily |
| `/exa/*` | Exa AI |
| `/perplexity/*` | Perplexity |

### Git & Dev
| Endpoint | Service |
|----------|---------|
| `/github/*` | GitHub API |
| `/gitlab/*` | GitLab API |
| `/bitbucket/*` | Bitbucket |

### Communication
| Endpoint | Service |
|----------|---------|
| `/slack/*` | Slack |
| `/discord/*` | Discord |
| `/telegram/*` | Telegram |
| `/twilio/*` | Twilio |
| `/sendgrid/*` | SendGrid |

### Monitoring
| Endpoint | Service |
|----------|---------|
| `/langsmith/*` | LangSmith |
| `/langfuse/*` | Langfuse |
| `/wandb/*` | Weights & Biases |
| `/arize/*` | Arize |

### Image & Media
| Endpoint | Service |
|----------|---------|
| `/replicate/*` | Replicate |
| `/stability/*` | Stability AI |
| `/cloudinary/*` | Cloudinary |
| `/elevenlabs/*` | ElevenLabs |

---

## 🏢 Use Cases

### 1. OpenClaw/Nanobot Integration
```yaml
# config.yaml
llm:
  provider: openrouter
  base_url: http://localhost:8080/openrouter
  api_key: dummy-key
  model: google/gemini-2.5-flash-preview
```

### 2. Multi-Agent Setup
```yaml
# docker-compose.yml
services:
  vault:
    image: agent-vault-proxy
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
  
  agent-1:
    image: my-agent
    environment:
      - OPENAI_API_KEY=dummy-key
      - OPENAI_BASE_URL=http://vault:8080/openai
  
  agent-2:
    image: my-agent
    environment:
      - OPENAI_API_KEY=dummy-key
      - OPENAI_BASE_URL=http://vault:8080/openai
```

### 3. CI/CD Pipelines
```bash
# No real keys in GitHub Secrets needed
export OPENAI_API_KEY=dummy-key
export OPENAI_BASE_URL=http://vault:8080/openai
pytest tests/
```

### 4. Development Teams
- Junior devs get only dummy keys
- Real keys stay in vault
- No fear of accidental commits

---

## 📚 Documentation

| Guide | Description |
|-------|-------------|
| [Remote Setup](docs/REMOTE_SETUP.md) | Vault on separate server |
| [HTTPS/TLS](docs/HTTPS_SETUP.md) | Setup TLS certificates |
| [Authentication](docs/AUTH_SETUP.md) | Agent-to-Vault auth |

---

## 🧪 Testing

```bash
# All tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=.
```

**Status:** 102/102 Tests passing ✅

---

## 🛡️ Security Model

```
┌─────────────┐     Dummy Key      ┌─────────────────┐     Real Key       ┌─────────────┐
│  AI Agent   │ ─────────────────► │  Agent Vault    │ ─────────────────► │   OpenAI    │
│             │                    │  Proxy          │                    │   API       │
│  - No real  │  Model, Params     │  ├─ Encrypted   │                    │             │
│    keys     │  (unchanged)       │  │   SQLite      │                    │             │
│  - Cannot   │                    │  ├─ CLI         │                    │             │
│    leak     │                    │  ├─ Middleware  │                    │             │
│             │                    │  └─ Audit Log   │                    │             │
└─────────────┘                    └─────────────────┘                    └─────────────┘
       ▲                                    │                                    │
       │                                    │                                    │
       └────────────────────────────────────┴────────────────────────────────────┘
                                    Response
```

---

## 🗺️ Roadmap to v1.0.0

- [x] Core Proxy
- [x] Encrypted SQLite Vault
- [x] Interactive CLI
- [x] Middleware Stack
- [x] Audit Logging
- [x] 100% Test Coverage
- [ ] RBAC (planned)
- [ ] Web Dashboard (planned)
- [ ] Key Rotation Automation (planned)

---

## 📄 License

MIT License

---

**Made with ❤️ for AI Agents that deserve secure API access**
