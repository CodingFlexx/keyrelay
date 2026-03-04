# Agent Vault Proxy v0.9.1

**Sichere API-Key-Verwaltung für AI Agents – Zero-Friction Integration**

> **Version:** 0.9.1 (Production Ready)  
> **Tests:** 102/102 passing (100%)  
> **Status:** Feature-complete, bereit für v1.0.0

---

## 🎯 Was ist das Agent Vault Proxy?

Ein **sicherer Proxy** der zwischen deinen AI Agents und externen APIs sitzt. Agents verwenden **Dummy-Keys**, der Proxy injiziert die **echten API-Keys** – ohne dass Agents jemals echte Keys sehen.

### Das Problem
```python
# ❌ VORHER: API-Keys im Agent-Code
OPENAI_API_KEY = "sk-abc123..."  # Gefahr: Leak, Git-Commit, Logs
```

### Die Lösung
```python
# ✅ NACHHER: Nur Dummy-Key nötig
OPENAI_API_KEY = "dummy-key"  # Proxy ersetzt mit echtem Key
BASE_URL = "http://vault:8080/openai"
```

---

## 🏗️ Zwei Architektur-Optionen

### Option 1: Lokal (Gleiche Maschine)

```
┌─────────────────────────────────────────┐
│  Host (Deine VM/Server)                 │
│  ┌─────────────┐    ┌─────────────────┐ │
│  │  AI Agent   │───►│  Agent Vault    │ │
│  │  (Root)     │    │  (Docker)       │ │
│  │             │◄───│  Port 8080      │ │
│  └─────────────┘    └─────────────────┘ │
│       localhost:8080                    │
└─────────────────────────────────────────┘
```

**Wann verwenden:**
- Einzelner Agent auf dedizierter VM
- Schnelle Einrichtung
- Entwicklung/Testing

**Vorteile:**
- ✅ Einfachstes Setup (docker-compose up)
- ✅ Geringste Latenz
- ✅ Keine Netzwerk-Konfiguration

**Sicherheit:**
- Agent hat theoretisch Root-Zugriff auf Vault möglich
- Defense in Depth: Encryption, Audit-Logging, Container-Isolation
- Für bösartige Agents: Siehe Option 2

---

### Option 2: Remote (Netzwerk-getrennt)

```
┌─────────────┐      Internet/VPN      ┌─────────────────┐
│   Agent     │  ═══════════════════►  │   Vault Server  │
│  (Lokal)    │    HTTPS + Auth Token  │  (Remote)       │
│             │  ◄═══════════════════   │  Port 443       │
└─────────────┘                        └─────────────────┘
       │                                      │
       │                                      │
       └─────────────── API-Keys ─────────────┘
              (nie beim Agent sichtbar)
```

**Wann verwenden:**
- Mehrere Agents zentral verwalten
- Höchste Sicherheitsanforderungen
- Production mit unterschiedlichen Agent-Teams

**Vorteile:**
- ✅ Physische Trennung = Höchste Sicherheit
- ✅ Zentrale Key-Verwaltung
- ✅ Agents können Vault nicht kompromittieren
- ✅ Audit-Logging zentralisiert

**Setup:**
- Siehe [Remote Setup Guide](docs/REMOTE_SETUP.md)
- TLS/HTTPS erforderlich
- Bearer Token Auth

---

## 💡 Warum Agent Vault Proxy verwenden?

| Problem | Lösung |
|---------|--------|
| **API-Keys in Git** | Keys niemals im Code |
| **Keys in Logs** | Proxy filtert Keys aus |
| **Rotation-Overhead** | Zentral rotieren, Agents unberührt |
| **Multi-Key Chaos** | Ein Vault, 30+ Services |
| **Keine Audit-Trails** | Jeder Request geloggt |
| **Agent-Kompromittierung** | Keys bleiben sicher im Vault |

### Zero-Friction Integration

**Was sich ändert:** Nur 2 Zeilen
```python
# VORHER
client = OpenAI(api_key="sk-real-key...")

# NACHHER
client = OpenAI(
    api_key="dummy-key",  # ← Änderung 1
    base_url="http://vault:8080/openai"  # ← Änderung 2
)
```

**Was gleich bleibt:** Alles andere
- Modelle
- Parameter (temperature, max_tokens)
- Request/Response Format
- Fehlerbehandlung
- SDK/Client

---

## 🚀 Quick Start

### 1. Repository klonen
```bash
git clone https://github.com/CodingFlexx/agent-vault-proxy.git
cd agent-vault-proxy
```

### 2. Konfigurieren

**Option A: CLI (Empfohlen)**
```bash
python cli.py
# → "Setup Vault" wählen
# → API-Keys hinzufügen
```

**Option B: Environment Variables**
```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

**Option C: secrets.json**
```bash
cp secrets.json.example secrets.json
# Datei editieren
```

### 3. Starten
```bash
docker-compose up -d
```

### 4. Testen
```bash
curl http://localhost:8080/health
```

---

## 📊 Features

### 🔐 Sicherheit
- **Verschlüsselter Vault** - SQLite mit Fernet (AES-128-CBC + HMAC)
- **Audit Logging** - Jeder Request mit Timestamp
- **Rate Limiting** - 60 req/min pro IP
- **Circuit Breaker** - Automatisches Failover
- **Path Traversal Protection** - Blocks `../`, Null Bytes
- **Request Size Limit** - 100MB max

### 🛠️ Management
- **Interactive CLI** - Typer + Rich UI
- **30+ Services** - LLMs, Vector DBs, Search, Git, Cloud
- **Health Checks** - `/health` und `/health/services`
- **Zero Config** - Docker-ready

### 🔌 Integration
- **OpenAI-kompatibel** - Funktioniert mit allen OpenAI-Clients
- **Drop-in Replacement** - Nur base_url ändern
- **Dummy Keys** - Beliebiger String funktioniert

---

## 📡 Unterstützte Services (30+)

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
# Keine echten Keys in GitHub Secrets nötig
export OPENAI_API_KEY=dummy-key
export OPENAI_BASE_URL=http://vault:8080/openai
pytest tests/
```

### 4. Entwicklerteams
- Junior-Devs bekommen nur Dummy-Keys
- Echte Keys bleiben im Vault
- Keine Angst vor Accidental Commits

---

## 📚 Dokumentation

| Guide | Beschreibung |
|-------|--------------|
| [Remote Setup](docs/REMOTE_SETUP.md) | Vault auf separatem Server |
| [HTTPS/TLS](docs/HTTPS_SETUP.md) | TLS-Zertifikate einrichten |
| [Authentication](docs/AUTH_SETUP.md) | Agent-to-Vault Auth |

---

## 🧪 Testing

```bash
# Alle Tests
python -m pytest tests/ -v

# Mit Coverage
python -m pytest tests/ --cov=.
```

**Status:** 102/102 Tests passing ✅

---

## 🛡️ Sicherheitsmodell

```
┌─────────────┐     Dummy Key      ┌─────────────────┐     Real Key       ┌─────────────┐
│  AI Agent   │ ─────────────────► │  Agent Vault    │ ─────────────────► │   OpenAI    │
│             │                    │  Proxy          │                    │   API       │
│  - Keine    │  Model, Params     │  ├─ Encrypted   │                    │             │
│    echten   │  (unchanged)       │  │   SQLite      │                    │             │
│    Keys     │                    │  ├─ CLI         │                    │             │
│  - Kann     │                    │  ├─ Middleware  │                    │             │
│    nicht    │                    │  └─ Audit Log   │                    │             │
│    leaken   │                    │                 │                    │             │
└─────────────┘                    └─────────────────┘                    └─────────────┘
       ▲                                    │                                    │
       │                                    │                                    │
       └────────────────────────────────────┴────────────────────────────────────┘
                                    Response
```

---

## 🗺️ Roadmap zu v1.0.0

- [x] Core Proxy
- [x] Encrypted SQLite Vault
- [x] Interactive CLI
- [x] Middleware Stack
- [x] Audit Logging
- [x] 100% Test Coverage
- [ ] RBAC (geplant)
- [ ] Web Dashboard (geplant)
- [ ] Key Rotation Automation (geplant)

---

## 📄 Lizenz

MIT License

---

**Made with ❤️ for AI Agents that deserve secure API access**
