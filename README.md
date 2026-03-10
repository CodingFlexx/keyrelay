# KeyRelay v0.9.1

> **A secure API key proxy for AI agents and tools.**
> KeyRelay securely injects your real API keys server-side, allowing your AI agents and clients to work purely with proxy endpoints without ever touching or seeing the actual provider secrets.

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-0.9.1-success)
![Tests](https://img.shields.io/badge/tests-120%2F120%20passed-success)

## 🌟 Why KeyRelay?

- **Zero API Key Leaks**: Keep your expensive API keys out of your agent code and local `.env` files.
- **Centralized Management**: Rotate, manage, and audit API access in one place.
- **Universal Proxy**: Supports 40+ external services (OpenAI, Anthropic, OpenRouter, GitHub, etc.).
- **RBAC**: Role-based access control with scoped proxy tokens for specific agents.

## 🔐 Security Model

- **Encrypted Vault**: All keys are stored in an SQLite vault using AES-128-CBC + HMAC (Fernet) encryption.
- **Audit Logging**: SQLite-based request audit logging with automatic rotation.
- **Rate Limiting & CORS**: Built-in security middleware, rate limiting, and configurable CORS origins.
- **Strict Authentication**: Configurable auth enforcement via `REQUIRE_AGENT_AUTH` (Default: true).
- **Service Scopes**: Least-privilege access instead of global access for agents.

## 🚀 Quick Start (Docker + Bootstrap UI)

The easiest way to start KeyRelay is via a simple Docker Run command. The official image is provided on Docker Hub.

### 1) Start the Container

```bash
docker run -d \
  -p 8080:8080 \
  -v keyrelay_data:/app/data \
  --name keyrelay \
  codingflexx/keyrelay:latest
```

*Upon first start, the container automatically bootstraps your encrypted SQLite database (`vault.db`) and securely generates the master encryption key (`.vault_key`) inside the persisted volume.*

### 2) First-Run Setup & UI

1. Open **`http://localhost:8080/admin/ui`** in your browser.
2. During your first visit, you will be greeted by the **First-Run Setup**. Create your initial `admin` user and password.
3. Once logged in, click **"+ Add Service Key"** to securely store your provider keys (e.g., OpenAI, Anthropic).
4. Click **"+ Add User / Agent"** and select **"Proxy User (Agent)"** to generate an access token for your AI agent.
5. Connect your agent using the provided proxy API key!

*(Note for automated deployments: You can bypass the UI setup by passing `-e BOOTSTRAP_ADMIN_USERNAME=admin` and `-e BOOTSTRAP_ADMIN_PASSWORD=your_password` to your docker run command).*

## 💻 Example Integration

### Direct Request
```bash
curl -X POST "http://localhost:8080/openai/chat/completions" \
  -H "Authorization: Bearer <your-proxy-user-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role":"user","content":"Hi"}]
  }'
```

### Python SDKs (OpenAI-compatible)
KeyRelay acts as a drop-in replacement for OpenAI-compatible SDKs (OpenClaw, LiteLLM, LangChain, etc.):

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/openai/v1",
    api_key="<your-proxy-user-key>",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

## 🛠 Advanced Deployments & Scenarios

KeyRelay supports three distinct security models (`KEYRELAY_SECURITY_MODE`), catering to different risk profiles.

1. **Local Native (Szenario 1)**
   - `hardened_local`
   - Agent runs natively on the host, KeyRelay in a container. Great for protecting against prompt-injection.
   - Example: `examples/docker-compose.local.yml`
2. **Multi-Container (Szenario 2)**
   - `hardened_local`
   - Agent and KeyRelay run in strictly separated containers on the same host.
   - Example: `examples/docker-compose.multi.yml`
3. **Remote Secure (Szenario 3)**
   - `remote_secure`
   - KeyRelay runs on a completely separate network host behind HTTPS/TLS, protecting against actively malicious agents.
   - Example: `examples/docker-compose.remote.yml`

For detailed setup instructions regarding TLS, remote hosting, and the Python CLI (`cli.py`), please refer to the [Documentation](docs/).

## 🩺 Health & Admin Endpoints

- `GET /health` - Public health check
- `GET /health/services` - Service status (Requires auth)
- `GET /admin/ui` - Admin Web Dashboard
- `GET /admin/audit-logs` - Recent logs (Admin only)
- `GET /admin/audit-stats` - Traffic statistics (Admin only)

## ⚙️ Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_VAULT_APP_DIR` | `/app/data` | Directory for the `vault.db` SQLite file |
| `REQUIRE_AGENT_AUTH` | `true` | Enforce proxy authentication |
| `KEYRELAY_SECURITY_MODE` | `hardened_local` | Security profile (`local`, `hardened_local`, `remote_secure`) |
| `CORS_ALLOWED_ORIGINS` | `localhost:3000,localhost:8080` | Allowed CORS origins |

## 📜 License

MIT License.
