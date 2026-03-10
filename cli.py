#!/usr/bin/env python3
"""
KeyRelay CLI v0.9 - Enhanced key management and onboarding.
"""

import json
import getpass
import os
import secrets
import subprocess
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

import click
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box

# Import database module
from database import (
    init_database, add_api_key, get_api_key, list_api_keys,
    remove_api_key, rotate_api_key, set_service_metadata,
    log_request, get_audit_logs, get_audit_stats,
    create_user, verify_user, verify_api_key, list_users, delete_user,
    get_encryption_key, encrypt_value, decrypt_value,
    get_vault_key_source, get_security_mode, get_service_metadata,
)
from cryptography.fernet import Fernet

console = Console()

# Version constant
VERSION = "0.9.1"

# App directory configuration
APP_DIR = Path(
    os.getenv("AGENT_VAULT_APP_DIR", str(Path.home() / ".agent-vault"))
).expanduser()
DB_PATH = APP_DIR / "vault.db"
KEY_FILE = APP_DIR / ".key"
SECURITY_MODE_ENV = "KEYRELAY_SECURITY_MODE"
DEPLOYMENT_SCENARIO_ENV = "KEYRELAY_DEPLOYMENT_SCENARIO"
ALLOW_SECRET_REVEAL_ENV = "ALLOW_SECRET_REVEAL"
VAULT_KEY_FILE_ENV = "AGENT_VAULT_KEY_FILE"
DEFAULT_VAULT_KEY_FILE = Path("/run/secrets/agent_vault_key")
DEFAULT_SCOPES = ["*"]

DEPLOYMENT_SCENARIOS = {
    "host_agent_container_relay": {
        "label": "Agent nativ auf dem Host, KeyRelay im Docker-Container",
        "security_mode": "hardened_local",
        "requires_remote": False,
        "requires_auth": True,
        "notes": [
            "Schuetzt gut gegen Prompt-Injection und versehentliche Leaks.",
            "Host-Root bleibt eine starke Angreiferposition gegen den Container.",
            "Docker-Secret und getrennte Volumes sind hier besonders wichtig.",
        ],
    },
    "separate_containers_same_host": {
        "label": "Agent und KeyRelay in separaten Containern auf demselben Host",
        "security_mode": "hardened_local",
        "requires_remote": False,
        "requires_auth": True,
        "notes": [
            "Empfohlen fuer denselben Host, wenn klare Container-Grenzen moeglich sind.",
            "Kein Docker-Socket und keine geteilten Secret-Volumes an den Agent-Container geben.",
            "Scopes pro Proxy-User begrenzen den Schaden bei kompromittiertem Agenten.",
        ],
    },
    "remote_keyrelay": {
        "label": "Agent lokal oder im Container, KeyRelay auf zweitem Host im Netzwerk",
        "security_mode": "remote_secure",
        "requires_remote": True,
        "requires_auth": True,
        "notes": [
            "Staerkstes Modell fuer aktive Angreifer und kompromittierte lokale Agenten.",
            "Relay nur per HTTPS/TLS exponieren und Admin-Zugriff getrennt halten.",
            "Proxy-User immer mit engen Service-Scopes anlegen.",
        ],
    },
}

SCENARIO_DOCS = {
    "host_agent_container_relay": ["README.md", "docs/DEPLOYMENT_SCENARIOS.md", "docs/AUTH_SETUP.md"],
    "separate_containers_same_host": ["README.md", "docs/DEPLOYMENT_SCENARIOS.md", "docs/AUTH_SETUP.md"],
    "remote_keyrelay": ["docs/REMOTE_SETUP.md", "docs/HTTPS_SETUP.md", "docs/AUTH_SETUP.md"],
}

SCOPE_PRESETS = {
    "llm": ["openai", "anthropic", "openrouter", "gemini", "groq", "cohere", "mistral", "deepseek"],
    "search": ["brave", "serpapi", "tavily", "exa", "perplexity", "bing", "google_custom_search"],
    "git": ["github", "gitlab", "bitbucket", "azure_devops"],
    "all": ["*"],
}

SERVICE_REQUIREMENTS = {
    "azure_openai": {
        "required_metadata": ["resource"],
        "key_hint": "Azure OpenAI API key, typischerweise 32+ Zeichen.",
    },
    "twilio": {
        "required_metadata": ["account_sid"],
        "key_hint": "Twilio Auth Token.",
    },
    "supabase": {
        "required_metadata": ["project"],
        "key_hint": "Supabase service key oder anon key.",
    },
    "auth0": {
        "required_metadata": ["domain"],
        "key_hint": "Auth0 Management/API token.",
    },
    "okta": {
        "required_metadata": ["domain"],
        "key_hint": "Okta API token.",
    },
    "shopify": {
        "required_metadata": ["shop"],
        "key_hint": "Shopify Admin API Access Token.",
    },
}

SERVICE_VALIDATION_TARGETS = {
    "openrouter": {"url": "https://openrouter.ai/api/v1/models", "method": "GET", "auth": "bearer"},
    "openai": {"url": "https://api.openai.com/v1/models", "method": "GET", "auth": "bearer"},
    "anthropic": {
        "url": "https://api.anthropic.com/v1/models",
        "method": "GET",
        "auth": "x-api-key",
        "extra_headers": {"anthropic-version": "2023-06-01"},
    },
    "groq": {"url": "https://api.groq.com/openai/v1/models", "method": "GET", "auth": "bearer"},
    "github": {"url": "https://api.github.com/user", "method": "GET", "auth": "token"},
    "huggingface": {"url": "https://api-inference.huggingface.co/status", "method": "GET", "auth": "bearer"},
}

IMPORT_PRIMARY_SECRET_FIELDS = (
    "api_key",
    "token",
    "pat",
    "secret_key",
    "access_key",
    "client_secret",
    "private_key",
)

IMPORT_SECRET_FIELDS = {
    "api_key",
    "token",
    "pat",
    "secret_key",
    "access_key",
    "client_secret",
    "private_key",
    "api_secret",
    "refresh_token",
    "password",
}

# Extended service definitions with 40+ services
SERVICES = {
    # LLM APIs
    "openrouter": {"icon": "🌐", "name": "OpenRouter", "description": "Universal LLM API gateway"},
    "openai": {"icon": "🤖", "name": "OpenAI", "description": "GPT models and embeddings"},
    "anthropic": {"icon": "🧠", "name": "Anthropic", "description": "Claude AI models"},
    "gemini": {"icon": "💎", "name": "Google Gemini", "description": "Google AI models"},
    "groq": {"icon": "⚡", "name": "Groq", "description": "Fast inference API"},
    "cohere": {"icon": "📝", "name": "Cohere", "description": "Text embeddings and generation"},
    "mistral": {"icon": "🌪️", "name": "Mistral AI", "description": "Open source LLMs"},
    "deepseek": {"icon": "🔍", "name": "DeepSeek", "description": "Chinese LLM provider"},
    "azure_openai": {"icon": "☁️", "name": "Azure OpenAI", "description": "Microsoft Azure AI"},
    "aws_bedrock": {"icon": "📦", "name": "AWS Bedrock", "description": "Amazon AI platform"},
    "ai21": {"icon": "🧩", "name": "AI21 Labs", "description": "Jurassic language models"},
    "aleph_alpha": {"icon": "🔤", "name": "Aleph Alpha", "description": "European LLM provider"},
    
    # Vector Databases
    "pinecone": {"icon": "🌲", "name": "Pinecone", "description": "Vector database"},
    "weaviate": {"icon": "🔮", "name": "Weaviate", "description": "AI-native vector DB"},
    "qdrant": {"icon": "🎯", "name": "Qdrant", "description": "Vector similarity search"},
    "chroma": {"icon": "🎨", "name": "Chroma", "description": "Embedding database"},
    "milvus": {"icon": "🦅", "name": "Milvus", "description": "Distributed vector DB"},
    "pgvector": {"icon": "🐘", "name": "pgvector", "description": "Postgres vector extension"},
    "redis_vector": {"icon": "🔴", "name": "Redis Vector", "description": "Redis vector search"},
    
    # Search APIs
    "brave": {"icon": "🦁", "name": "Brave Search", "description": "Privacy-focused search"},
    "serpapi": {"icon": "🔎", "name": "SerpAPI", "description": "Google search API"},
    "tavily": {"icon": "📊", "name": "Tavily", "description": "AI search engine"},
    "exa": {"icon": "🔬", "name": "Exa", "description": "Neural search"},
    "perplexity": {"icon": "❓", "name": "Perplexity", "description": "AI answer engine"},
    "bing": {"icon": "🔷", "name": "Bing Search", "description": "Microsoft search API"},
    "google_custom_search": {"icon": "🔍", "name": "Google Custom Search", "description": "Programmable search"},
    
    # Git & Dev
    "github": {"icon": "🐙", "name": "GitHub", "description": "Code repository"},
    "gitlab": {"icon": "🦊", "name": "GitLab", "description": "DevOps platform"},
    "bitbucket": {"icon": "🪣", "name": "Bitbucket", "description": "Git repository hosting"},
    "azure_devops": {"icon": "🔷", "name": "Azure DevOps", "description": "Microsoft DevOps"},
    
    # Cloud & Storage
    "aws": {"icon": "☁️", "name": "AWS", "description": "Amazon Web Services"},
    "gcp": {"icon": "🔵", "name": "Google Cloud", "description": "Google Cloud Platform"},
    "azure": {"icon": "🔷", "name": "Azure", "description": "Microsoft Azure"},
    "supabase": {"icon": "⚡", "name": "Supabase", "description": "Firebase alternative"},
    "firebase": {"icon": "🔥", "name": "Firebase", "description": "Google app platform"},
    "mongodb": {"icon": "🍃", "name": "MongoDB", "description": "NoSQL database"},
    "planetscale": {"icon": "🪐", "name": "PlanetScale", "description": "MySQL platform"},
    "neon": {"icon": "💡", "name": "Neon", "description": "Serverless Postgres"},
    "upstash": {"icon": "⚡", "name": "Upstash", "description": "Serverless Redis/Kafka"},
    
    # Communication
    "slack": {"icon": "💬", "name": "Slack", "description": "Team messaging"},
    "discord": {"icon": "🎮", "name": "Discord", "description": "Community chat"},
    "telegram": {"icon": "✈️", "name": "Telegram", "description": "Secure messaging"},
    "twilio": {"icon": "📞", "name": "Twilio", "description": "Communication APIs"},
    "sendgrid": {"icon": "📧", "name": "SendGrid", "description": "Email delivery"},
    "mailgun": {"icon": "🔫", "name": "Mailgun", "description": "Email service"},
    "postmark": {"icon": "📮", "name": "Postmark", "description": "Transactional email"},
    "resend": {"icon": "📤", "name": "Resend", "description": "Email for developers"},
    
    # Monitoring & Analytics
    "langsmith": {"icon": "🔧", "name": "LangSmith", "description": "LLM observability"},
    "langfuse": {"icon": "📈", "name": "Langfuse", "description": "LLM analytics"},
    "weights_biases": {"icon": "🏋️", "name": "Weights & Biases", "description": "ML experiment tracking"},
    "arize": {"icon": "📊", "name": "Arize", "description": "ML observability"},
    "phoenix": {"icon": "🔥", "name": "Phoenix", "description": "LLM observability"},
    "promptlayer": {"icon": "📋", "name": "PromptLayer", "description": "Prompt management"},
    "helicone": {"icon": "🚁", "name": "Helicone", "description": "LLM monitoring"},
    
    # Image & Media
    "replicate": {"icon": "🔄", "name": "Replicate", "description": "ML model hosting"},
    "stability": {"icon": "🎭", "name": "Stability AI", "description": "Image generation"},
    "cloudinary": {"icon": "☁️", "name": "Cloudinary", "description": "Media management"},
    "imgix": {"icon": "🖼️", "name": "Imgix", "description": "Image processing"},
    "unsplash": {"icon": "📷", "name": "Unsplash", "description": "Stock photos"},
    
    # Other AI Services
    "huggingface": {"icon": "🤗", "name": "Hugging Face", "description": "ML community"},
    "assemblyai": {"icon": "🎤", "name": "AssemblyAI", "description": "Speech recognition"},
    "elevenlabs": {"icon": "🗣️", "name": "ElevenLabs", "description": "Voice synthesis"},
    "openvoice": {"icon": "🎙️", "name": "OpenVoice", "description": "Voice cloning"},
    "whisper": {"icon": "👂", "name": "Whisper API", "description": "Speech-to-text"},
    "deepgram": {"icon": "🎧", "name": "Deepgram", "description": "Voice AI"},
    "rev_ai": {"icon": "📝", "name": "Rev.ai", "description": "Speech-to-text"},
    
    # Productivity & Collaboration
    "notion": {"icon": "📓", "name": "Notion", "description": "Workspace & docs"},
    "airtable": {"icon": "🗂️", "name": "Airtable", "description": "Database spreadsheet"},
    "trello": {"icon": "📋", "name": "Trello", "description": "Project management"},
    "asana": {"icon": "✅", "name": "Asana", "description": "Task management"},
    "linear": {"icon": "📐", "name": "Linear", "description": "Issue tracking"},
    "jira": {"icon": "🐛", "name": "Jira", "description": "Project management"},
    "confluence": {"icon": "📄", "name": "Confluence", "description": "Documentation"},
    
    # Payment & Commerce
    "stripe": {"icon": "💳", "name": "Stripe", "description": "Payment processing"},
    "paypal": {"icon": "💰", "name": "PayPal", "description": "Payment platform"},
    "shopify": {"icon": "🛒", "name": "Shopify", "description": "E-commerce platform"},
    
    # Security & Auth
    "auth0": {"icon": "🔐", "name": "Auth0", "description": "Authentication"},
    "okta": {"icon": "🆗", "name": "Okta", "description": "Identity management"},
    "1password": {"icon": "🔑", "name": "1Password", "description": "Password manager"},
}


def print_banner():
    """Print welcome banner."""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🔐  [bold cyan]KEYRELAY v0.9[/bold cyan] - Secure API Key Relay            ║
║                                                          ║
║   Guided setup, encrypted vault, audit logging, RBAC     ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""
    console.print(Panel(banner, border_style="cyan", box=box.DOUBLE))


SERVICE_CATEGORIES = {
    "LLM APIs": [
        "openrouter", "openai", "anthropic", "gemini", "groq", "cohere",
        "mistral", "deepseek", "azure_openai", "aws_bedrock", "ai21", "aleph_alpha",
    ],
    "Vector Databases": [
        "pinecone", "weaviate", "qdrant", "chroma", "milvus", "pgvector", "redis_vector",
    ],
    "Search APIs": [
        "brave", "serpapi", "tavily", "exa", "perplexity", "bing", "google_custom_search",
    ],
    "Git & Dev": ["github", "gitlab", "bitbucket", "azure_devops"],
    "Cloud & Storage": [
        "aws", "gcp", "azure", "supabase", "firebase", "mongodb",
        "planetscale", "neon", "upstash",
    ],
    "Communication": ["slack", "discord", "telegram", "twilio", "sendgrid", "mailgun", "postmark", "resend"],
    "Monitoring & Analytics": [
        "langsmith", "langfuse", "weights_biases", "arize", "phoenix", "promptlayer", "helicone",
    ],
    "Image & Media": ["replicate", "stability", "cloudinary", "imgix", "unsplash"],
    "Other AI Services": ["huggingface", "assemblyai", "elevenlabs", "openvoice", "whisper", "deepgram", "rev_ai"],
    "Productivity & Collaboration": ["notion", "airtable", "trello", "asana", "linear", "jira", "confluence"],
    "Payment & Commerce": ["stripe", "paypal", "shopify"],
    "Security & Auth": ["auth0", "okta", "1password"],
}

ENV_TO_SERVICE = {
    "OPENROUTER_API_KEY": "openrouter",
    "OPENAI_API_KEY": "openai",
    "ANTHROPIC_API_KEY": "anthropic",
    "GEMINI_API_KEY": "gemini",
    "GROQ_API_KEY": "groq",
    "COHERE_API_KEY": "cohere",
    "MISTRAL_API_KEY": "mistral",
    "DEEPSEEK_API_KEY": "deepseek",
    "AZURE_OPENAI_API_KEY": "azure_openai",
    "PINECONE_API_KEY": "pinecone",
    "WEAVIATE_API_KEY": "weaviate",
    "QDRANT_API_KEY": "qdrant",
    "BRAVE_API_KEY": "brave",
    "SERPAPI_KEY": "serpapi",
    "TAVILY_API_KEY": "tavily",
    "EXA_API_KEY": "exa",
    "PERPLEXITY_API_KEY": "perplexity",
    "GITHUB_PAT": "github",
    "GITLAB_TOKEN": "gitlab",
    "BITBUCKET_TOKEN": "bitbucket",
    "SUPABASE_KEY": "supabase",
    "FIREBASE_TOKEN": "firebase",
    "SLACK_TOKEN": "slack",
    "DISCORD_TOKEN": "discord",
    "TELEGRAM_BOT_TOKEN": "telegram",
    "TWILIO_AUTH_TOKEN": "twilio",
    "SENDGRID_API_KEY": "sendgrid",
    "LANGSMITH_API_KEY": "langsmith",
    "LANGFUSE_PUBLIC_KEY": "langfuse",
    "WANDB_API_KEY": "weights_biases",
    "ARIZE_API_KEY": "arize",
    "REPLICATE_API_TOKEN": "replicate",
    "STABILITY_API_KEY": "stability",
    "CLOUDINARY_API_KEY": "cloudinary",
    "HF_API_TOKEN": "huggingface",
    "ASSEMBLYAI_API_KEY": "assemblyai",
    "ELEVENLABS_API_KEY": "elevenlabs",
}


def _require_auth_enabled() -> bool:
    return os.getenv("REQUIRE_AGENT_AUTH", "true").strip().lower() in {"1", "true", "yes", "on"}


def _is_reveal_enabled() -> bool:
    return os.getenv(ALLOW_SECRET_REVEAL_ENV, "false").strip().lower() in {"1", "true", "yes", "on"}


def _normalize_scope_values(raw_values: Optional[Tuple[str, ...]]) -> List[str]:
    if not raw_values:
        return list(DEFAULT_SCOPES)
    scopes: List[str] = []
    for raw in raw_values:
        for scope in raw.split(","):
            cleaned = scope.strip().lower()
            if cleaned:
                scopes.append(cleaned)
    unique_sorted = sorted(set(scopes))
    return unique_sorted or list(DEFAULT_SCOPES)


def _choose_deployment_scenario() -> str:
    table = Table(title="Deployment-Szenarien", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Szenario", style="bold")
    table.add_column("Security-Modus")
    scenario_ids = list(DEPLOYMENT_SCENARIOS.keys())
    for idx, scenario_id in enumerate(scenario_ids, start=1):
        scenario = DEPLOYMENT_SCENARIOS[scenario_id]
        table.add_row(str(idx), scenario["label"], scenario["security_mode"])
    console.print(table)
    choice = click.prompt("Szenario waehlen", type=int, default=2)
    if choice < 1 or choice > len(scenario_ids):
        raise click.ClickException("Ungueltiges Deployment-Szenario.")
    return scenario_ids[choice - 1]


def _render_persistent_env_hint(assignments: Dict[str, str]) -> None:
    if not assignments:
        return
    console.print("\n[bold]Persistente Konfiguration:[/bold]")
    for key, value in assignments.items():
        console.print(f"[dim]export {key}={value}[/dim]")

    default_path = Path(".keyrelay.setup.env")
    if Confirm.ask(f"Konfig in {default_path} schreiben?", default=True):
        lines = [f"{key}={value}" for key, value in assignments.items()]
        default_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        console.print(f"[green]Gespeichert:[/green] {default_path}")


def _required_metadata_fields(service: str) -> List[str]:
    config = SERVICE_REQUIREMENTS.get(service, {})
    required = config.get("required_metadata", [])
    return [str(item) for item in required]


def _prompt_required_metadata(
    service: str,
    metadata: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    enriched = dict(metadata or {})
    for field in _required_metadata_fields(service):
        if enriched.get(field):
            continue
        prompt_map = {
            "resource": "Azure resource name",
            "account_sid": "Twilio Account SID",
            "project": "Supabase project ID",
            "domain": "Domain (ohne Protokoll)",
            "shop": "Shop Name (ohne .myshopify.com)",
        }
        value = click.prompt(prompt_map.get(field, f"{field}"), default="", show_default=False).strip()
        if value:
            enriched[field] = value
    return enriched


def _validate_key_format(service: str, key: str) -> Optional[str]:
    stripped = key.strip()
    if len(stripped) < 10:
        return "Der Key wirkt ungueltig kurz."
    heuristics = {
        "openai": ("sk-", "OpenAI Keys beginnen meistens mit 'sk-'"),
        "openrouter": ("sk-or-", "OpenRouter Keys beginnen meistens mit 'sk-or-'"),
        "anthropic": ("sk-ant-", "Anthropic Keys beginnen meistens mit 'sk-ant-'"),
        "groq": ("gsk_", "Groq Keys beginnen meistens mit 'gsk_'"),
        "github": ("gh", "GitHub Token beginnen oft mit 'ghp_'/`github_pat_`"),
    }
    if service in heuristics:
        prefix, hint = heuristics[service]
        if not stripped.startswith(prefix):
            return hint
    return None


def _validate_service_key_remote(
    service: str,
    key: str,
    metadata: Optional[Dict[str, str]] = None,
) -> Tuple[str, str]:
    target = SERVICE_VALIDATION_TARGETS.get(service)
    if not target:
        return "skipped", "Kein automatischer Live-Test fuer diesen Service konfiguriert."

    headers: Dict[str, str] = {"Accept": "application/json"}
    auth_mode = target.get("auth")
    if auth_mode == "bearer":
        headers["Authorization"] = f"Bearer {key}"
    elif auth_mode == "token":
        headers["Authorization"] = f"token {key}"
    elif auth_mode == "x-api-key":
        headers["x-api-key"] = key

    extra_headers = target.get("extra_headers", {})
    if isinstance(extra_headers, dict):
        headers.update({str(k): str(v) for k, v in extra_headers.items()})

    url = str(target["url"])
    timeout = httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.request(str(target.get("method", "GET")), url, headers=headers)
        if response.status_code in (200, 201, 202):
            return "valid", f"Live-Test erfolgreich ({response.status_code})."
        if response.status_code in (401, 403):
            return "invalid", f"Provider antwortet mit {response.status_code} (Auth fehlgeschlagen)."
        return "warning", f"Provider antwortet mit {response.status_code}."
    except httpx.TimeoutException:
        return "warning", "Live-Test Timeout."
    except Exception as exc:
        return "warning", f"Live-Test Fehler: {exc}"


def _collect_user_scopes_interactive(default_scope: str = "llm") -> List[str]:
    table = Table(title="Scope-Auswahl", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Preset", style="bold")
    table.add_column("Beschreibung")
    presets = [
        ("llm", "Nur LLM-Provider"),
        ("search", "Nur Search-APIs"),
        ("git", "Nur Git/Dev APIs"),
        ("all", "Alle Services"),
        ("custom", "Services manuell auswaehlen"),
    ]
    for idx, (preset, description) in enumerate(presets, start=1):
        table.add_row(str(idx), preset, description)
    console.print(table)

    default_choice = next((idx for idx, (preset, _) in enumerate(presets, start=1) if preset == default_scope), 1)
    choice = click.prompt("Scope-Preset", type=int, default=default_choice)
    if choice < 1 or choice > len(presets):
        return list(DEFAULT_SCOPES)
    preset = presets[choice - 1][0]
    if preset == "custom":
        selected: List[str] = []
        while True:
            service = select_service_interactive()
            if not service:
                break
            selected.append(service)
            if not Confirm.ask("Weiteren Service hinzufuegen?", default=False):
                break
        return sorted(set(selected)) if selected else list(DEFAULT_SCOPES)
    return list(SCOPE_PRESETS.get(preset, DEFAULT_SCOPES))


def _store_service_key(
    service: str,
    key: str,
    metadata: Optional[Dict[str, str]] = None,
    secondary_secrets: Optional[Dict[str, str]] = None,
) -> bool:
    with console.status("[bold green]Saving API key..."):
        success = add_api_key(service, key, metadata if metadata else None, secondary_secrets=secondary_secrets)
    if success and metadata:
        set_service_metadata(service, **metadata)
    return success


def _generate_fernet_key() -> str:
    return Fernet.generate_key().decode()


def _collect_service_metadata(
    service: str,
    existing_metadata: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    metadata: Dict[str, str] = dict(existing_metadata or {})
    requirement = SERVICE_REQUIREMENTS.get(service, {})
    if requirement.get("key_hint"):
        console.print(f"[dim]Hinweis:[/dim] {requirement['key_hint']}")

    if service in ["azure_openai"]:
        value = click.prompt("Resource name", default=metadata.get("resource", ""), show_default=False).strip()
        if value:
            metadata["resource"] = value
    elif service in ["weaviate", "qdrant", "milvus"]:
        value = click.prompt("Cluster name (optional)", default=metadata.get("cluster", ""), show_default=False).strip()
        if value:
            metadata["cluster"] = value
    elif service == "supabase":
        value = click.prompt("Project ID", default=metadata.get("project", ""), show_default=False).strip()
        if value:
            metadata["project"] = value
    elif service == "cloudinary":
        value = click.prompt("Cloud name (optional)", default=metadata.get("cloud_name", ""), show_default=False).strip()
        if value:
            metadata["cloud_name"] = value
    elif service == "twilio":
        value = click.prompt("Account SID", default=metadata.get("account_sid", ""), show_default=False).strip()
        if value:
            metadata["account_sid"] = value
    elif service in ["aws", "aws_bedrock"]:
        value = click.prompt("AWS region (optional)", default=metadata.get("region", "us-east-1")).strip()
        if value:
            metadata["region"] = value
    elif service in ["auth0", "okta"]:
        value = click.prompt("Domain (without protocol)", default=metadata.get("domain", ""), show_default=False).strip()
        if value:
            metadata["domain"] = value
    elif service == "shopify":
        value = click.prompt("Shop name (without .myshopify.com)", default=metadata.get("shop", ""), show_default=False).strip()
        if value:
            metadata["shop"] = value
    return _prompt_required_metadata(service, {k: v for k, v in metadata.items() if v is not None})


def _choose_service_from_list(services: List[str], title: str) -> Optional[str]:
    if not services:
        return None
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Service", style="bold")
    table.add_column("Description")
    for idx, service_name in enumerate(services, start=1):
        info = SERVICES.get(service_name, {})
        table.add_row(
            str(idx),
            f"{info.get('icon', '🔑')} {service_name}",
            info.get("description", "Custom service"),
        )
    console.print(table)
    choice = click.prompt("Nummer waehlen", type=int)
    if choice < 1 or choice > len(services):
        console.print("[red]Ungueltige Auswahl[/red]")
        return None
    return services[choice - 1]


def select_service_interactive(search: Optional[str] = None) -> Optional[str]:
    """Interactive category-first service picker."""
    if search:
        filtered = [s for s in SERVICES if search.lower() in s.lower() or search.lower() in SERVICES[s]["name"].lower()]
        return _choose_service_from_list(filtered, f"Gefilterte Services fuer '{search}'")

    category_names = list(SERVICE_CATEGORIES.keys())
    table = Table(title="Service-Kategorien", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Kategorie", style="bold")
    table.add_column("Anzahl")
    for idx, category in enumerate(category_names, start=1):
        table.add_row(str(idx), category, str(len(SERVICE_CATEGORIES[category])))
    table.add_row("0", "Custom Service", "frei")
    console.print(table)

    category_choice = click.prompt("Kategorie waehlen", type=int, default=1)
    if category_choice == 0:
        return click.prompt("Custom service name").strip().lower().replace(" ", "_")
    if category_choice < 1 or category_choice > len(category_names):
        console.print("[red]Ungueltige Kategorie[/red]")
        return None
    category = category_names[category_choice - 1]
    return _choose_service_from_list(SERVICE_CATEGORIES[category], f"Services in '{category}'")


def run_doctor_checks(validate_services: bool = False) -> Tuple[List[Dict[str, str]], bool]:
    """Run setup and security checks used by doctor/start commands."""
    checks: List[Dict[str, str]] = []
    success = True

    mode = get_security_mode()
    scenario_id = os.getenv(DEPLOYMENT_SCENARIO_ENV, "").strip()
    checks.append({"name": "Security Mode", "status": "pass", "detail": mode})
    if scenario_id in DEPLOYMENT_SCENARIOS:
        checks.append({"name": "Deployment Scenario", "status": "pass", "detail": DEPLOYMENT_SCENARIOS[scenario_id]["label"]})
    elif scenario_id:
        checks.append({"name": "Deployment Scenario", "status": "warn", "detail": f"Unbekannt: {scenario_id}"})
    else:
        checks.append({"name": "Deployment Scenario", "status": "warn", "detail": "Nicht gesetzt"})

    try:
        _ = get_encryption_key()
        key_source = get_vault_key_source()
        if key_source.startswith("file:"):
            checks.append({"name": "Vault Key Source", "status": "pass", "detail": key_source})
        else:
            status = "warn" if mode in {"hardened_local", "remote_secure"} else "pass"
            checks.append({
                "name": "Vault Key Source",
                "status": status,
                "detail": f"{key_source} (Datei/Secret-Mount empfohlen)",
            })
            if mode == "remote_secure":
                success = False
    except Exception as exc:
        checks.append({"name": "Vault Key Source", "status": "fail", "detail": str(exc)})
        success = False

    if DB_PATH.exists():
        checks.append({"name": "Vault DB", "status": "pass", "detail": str(DB_PATH)})
        try:
            perms = oct(DB_PATH.stat().st_mode & 0o777)
            if perms != "0o600":
                checks.append({"name": "DB Permissions", "status": "warn", "detail": f"{perms} (empfohlen: 0o600)"})
            else:
                checks.append({"name": "DB Permissions", "status": "pass", "detail": perms})
        except Exception as exc:
            checks.append({"name": "DB Permissions", "status": "warn", "detail": str(exc)})
    else:
        checks.append({"name": "Vault DB", "status": "fail", "detail": "Nicht gefunden. Erst 'python3 cli.py init' ausfuehren."})
        success = False

    try:
        keys = list_api_keys()
        if keys:
            checks.append({"name": "API Keys", "status": "pass", "detail": f"{len(keys)} konfiguriert"})
        else:
            checks.append({"name": "API Keys", "status": "warn", "detail": "Keine API Keys konfiguriert"})
    except Exception as exc:
        checks.append({"name": "API Keys", "status": "fail", "detail": str(exc)})
        success = False

    try:
        probe = "doctor-probe-value"
        encrypted = encrypt_value(probe)
        decrypted = decrypt_value(encrypted)
        if decrypted == probe:
            checks.append({"name": "Encryption Roundtrip", "status": "pass", "detail": "OK"})
        else:
            checks.append({"name": "Encryption Roundtrip", "status": "fail", "detail": "Mismatch"})
            success = False
    except Exception as exc:
        checks.append({"name": "Encryption Roundtrip", "status": "fail", "detail": str(exc)})
        success = False

    try:
        users = list_users()
        if _require_auth_enabled() and not users:
            checks.append({"name": "Proxy Users", "status": "warn", "detail": "REQUIRE_AGENT_AUTH=true, aber kein User vorhanden"})
        else:
            checks.append({"name": "Proxy Users", "status": "pass", "detail": f"{len(users)} vorhanden"})
        scoped_users = [u for u in users if u.get("role") != "admin" and u.get("scopes") and u.get("scopes") != ["*"]]
        if users and not scoped_users:
            checks.append({
                "name": "Least-Privilege Scopes",
                "status": "warn",
                "detail": "Keine eingeschraenkten User-Scopes gefunden",
            })
        elif scoped_users:
            checks.append({
                "name": "Least-Privilege Scopes",
                "status": "pass",
                "detail": f"{len(scoped_users)} User mit eingeschraenkten Scopes",
            })
    except Exception as exc:
        checks.append({"name": "Proxy Users", "status": "fail", "detail": str(exc)})
        success = False

    if mode == "remote_secure" and not _require_auth_enabled():
        checks.append({
            "name": "Auth Policy",
            "status": "fail",
            "detail": "remote_secure braucht REQUIRE_AGENT_AUTH=true",
        })
        success = False
    elif not _require_auth_enabled():
        checks.append({"name": "Auth Policy", "status": "warn", "detail": "REQUIRE_AGENT_AUTH=false (nur lokal empfohlen)"})
    else:
        checks.append({"name": "Auth Policy", "status": "pass", "detail": "REQUIRE_AGENT_AUTH=true"})

    if scenario_id == "remote_keyrelay":
        cors_origins_value = os.getenv("CORS_ALLOWED_ORIGINS", "")
        if not cors_origins_value or "localhost" in cors_origins_value:
            checks.append({
                "name": "Remote Exposure",
                "status": "warn",
                "detail": "Remote-Szenario: CORS/Exposure fuer echte Hostnamen pruefen",
            })

    if _is_reveal_enabled():
        checks.append({
            "name": "Secret Reveal",
            "status": "warn",
            "detail": f"{ALLOW_SECRET_REVEAL_ENV}=true aktiviert Klartext-Ausgaben",
        })
    else:
        checks.append({"name": "Secret Reveal", "status": "pass", "detail": "Klartext-Reveal standardmaessig deaktiviert"})

    for dependency in ["fastapi", "uvicorn", "httpx", "cryptography", "rich", "click"]:
        try:
            __import__(dependency)
            checks.append({"name": f"Dependency '{dependency}'", "status": "pass", "detail": "OK"})
        except Exception:
            checks.append({"name": f"Dependency '{dependency}'", "status": "fail", "detail": "Nicht installiert"})
            success = False

    try:
        hidepid_path = Path("/proc/self/environ")
        if hidepid_path.exists():
            import stat
            proc_mount_info = Path("/proc/mounts").read_text(encoding="utf-8", errors="ignore")
            if "hidepid=" in proc_mount_info:
                checks.append({"name": "proc hidepid", "status": "pass", "detail": "/proc mit hidepid gemountet"})
            else:
                checks.append({
                    "name": "proc hidepid",
                    "status": "warn",
                    "detail": "/proc ohne hidepid - andere Prozesse koennen Env-Vars lesen. "
                              "Empfehlung: mount -o remount,hidepid=2 /proc"
                })
    except Exception:
        pass

    cors_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")
    if cors_origins and "*" in cors_origins:
        checks.append({"name": "CORS Origins", "status": "warn", "detail": "Wildcard '*' in CORS_ALLOWED_ORIGINS ist unsicher"})
    elif cors_origins:
        checks.append({"name": "CORS Origins", "status": "pass", "detail": f"{len(cors_origins.split(','))} Origins konfiguriert"})
    else:
        checks.append({"name": "CORS Origins", "status": "pass", "detail": "Standard (localhost)"})

    if validate_services:
        keys = list_api_keys()
        for key_info in keys:
            service_name = key_info.get("service_name")
            if not service_name:
                continue
            value = get_api_key(service_name)
            if not value:
                checks.append({
                    "name": f"Service Validation {service_name}",
                    "status": "fail",
                    "detail": "Kein aktiver Key gefunden",
                })
                success = False
                continue
            validation_status, detail = _validate_service_key_remote(service_name, value, get_service_metadata(service_name))
            mapped_status = {
                "valid": "pass",
                "invalid": "fail",
                "warning": "warn",
                "skipped": "warn",
            }.get(validation_status, "warn")
            checks.append({
                "name": f"Service Validation {service_name}",
                "status": mapped_status,
                "detail": detail,
            })
            if mapped_status == "fail":
                success = False

    fail_count = len([c for c in checks if c["status"] == "fail"])
    warn_count = len([c for c in checks if c["status"] == "warn"])
    if fail_count:
        readiness = "unsicher konfiguriert"
        readiness_status = "fail"
    elif warn_count:
        readiness = "teilweise bereit"
        readiness_status = "warn"
    else:
        readiness = "einsatzbereit"
        readiness_status = "pass"
    checks.append({"name": "Scenario Readiness", "status": readiness_status, "detail": readiness})

    return checks, success


def render_doctor_results(checks: List[Dict[str, str]]) -> None:
    table = Table(title="KeyRelay Doctor Report", box=box.ROUNDED)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")
    for entry in checks:
        status = entry["status"]
        if status == "pass":
            status_label = "[green]PASS[/green]"
        elif status == "warn":
            status_label = "[yellow]WARN[/yellow]"
        else:
            status_label = "[red]FAIL[/red]"
        table.add_row(entry["name"], status_label, entry["detail"])
    console.print(table)


def _infer_service_from_env_var(env_var: str) -> str:
    if env_var in ENV_TO_SERVICE:
        return ENV_TO_SERVICE[env_var]
    normalized = env_var.strip().lower()
    for suffix in ("_api_key", "_token", "_pat", "_key"):
        if normalized.endswith(suffix):
            normalized = normalized[: -len(suffix)]
            break
    return normalized


def _parse_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if value:
            values[key] = value
    return values


def _load_json_import(path: Path) -> Dict[str, Dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise click.ClickException("JSON root must be an object")
    normalized: Dict[str, Dict[str, str]] = {}
    for service, data in payload.items():
        if not isinstance(data, dict):
            continue
        key_value = None
        for field in IMPORT_PRIMARY_SECRET_FIELDS:
            if data.get(field):
                key_value = str(data[field])
                break
        if not key_value:
            continue
        metadata: Dict[str, str] = {}
        secondary_secrets: Dict[str, str] = {}
        for key, value in data.items():
            if not value:
                continue
            if key in IMPORT_PRIMARY_SECRET_FIELDS:
                continue
            if key in IMPORT_SECRET_FIELDS or any(
                token in key.lower() for token in ("secret", "token", "password", "private")
            ):
                secondary_secrets[key] = str(value)
            else:
                metadata[key] = str(value)
        normalized[service] = {
            "key": key_value,
            "__secondary_secrets__": json.dumps(secondary_secrets),
            **metadata,
        }
    return normalized


def _mask_value(value: str) -> str:
    if not value:
        return "****"
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _start_server(host: str, port: int) -> None:
    command = ["uvicorn", "main:app", "--host", host, "--port", str(port)]
    console.print(f"[green]Starte KeyRelay Proxy auf http://{host}:{port}[/green]")
    subprocess.run(command, check=True)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.9.1", prog_name="keyrelay")
@click.pass_context
def cli(ctx):
    """KeyRelay CLI - Secure API key management and guided onboarding."""
    ctx.ensure_object(dict)
    ctx.obj["db_exists"] = DB_PATH.exists()

    # Commands that can run before DB initialization.
    pre_init_commands = {"init", "setup", "help", "doctor"}
    if not DB_PATH.exists() and ctx.invoked_subcommand not in pre_init_commands:
        console.print("[yellow]⚠️  Vault not initialized![/yellow]")
        console.print("\n[dim]Run:[/dim] [cyan]python3 cli.py setup[/cyan] [dim](recommended)[/dim]")
        console.print("[dim]or:[/dim] [cyan]python3 cli.py init[/cyan]")
        raise click.Abort()


@cli.command(epilog="Beispiel:\n  python3 cli.py init")
def init():
    """Initialize the vault database."""
    print_banner()
    
    if DB_PATH.exists():
        if not Confirm.ask("Vault already exists. Reinitialize?", default=False):
            console.print("[dim]Aborted.[/dim]")
            return
    
    with console.status("[bold green]Initializing vault..."):
        init_database()
    
    console.print("\n[bold green]Vault erfolgreich initialisiert.[/bold green]")
    console.print(f"[dim]Location:[/dim] {APP_DIR}")
    console.print(f"[dim]Database:[/dim] {DB_PATH}")
    
    console.print("\n[bold]Next steps:[/bold]")
    console.print("  [cyan]python3 cli.py add-key[/cyan]      # Add your first API key")
    console.print("  [cyan]python3 cli.py list-keys[/cyan]    # View all services")
    console.print("  [cyan]python3 cli.py user-create[/cyan]  # Create admin user")


@cli.command(epilog="Beispiel:\n  python3 cli.py setup")
def setup():
    """Guided first-time setup wizard."""
    print_banner()
    console.print("[bold]Gefuehrtes Setup[/bold] - von 0 bis lauffaehiger Proxy in wenigen Schritten.\n")

    scenario_id = _choose_deployment_scenario()
    scenario = DEPLOYMENT_SCENARIOS[scenario_id]
    mode = scenario["security_mode"]
    console.print(
        Panel(
            "\n".join(f"- {note}" for note in scenario["notes"]),
            title=f"Szenario: {scenario['label']}",
            border_style="cyan",
        )
    )

    try:
        key_source = get_vault_key_source()
    except Exception:
        generated = _generate_fernet_key()
        suggested_path = click.prompt(
            "Pfad fuer Vault-Key-Datei",
            default=str(DEFAULT_VAULT_KEY_FILE),
            show_default=True,
        ).strip()
        key_path = Path(suggested_path).expanduser()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(generated + "\n", encoding="utf-8")
        key_path.chmod(0o600)
        os.environ[VAULT_KEY_FILE_ENV] = str(key_path)
        key_source = f"file:{key_path}"
        console.print("[green]Vault-Key-Datei erstellt.[/green]")
        console.print(
            f"[dim]Persistent setzen:[/dim] export {VAULT_KEY_FILE_ENV}=\"{key_path}\""
        )

    if DB_PATH.exists():
        console.print("[green]Vorhandene Vault-DB erkannt.[/green]")
    else:
        with console.status("[bold green]Initialisiere Vault..."):
            init_database()
        console.print("[green]Vault initialisiert.[/green]")

    os.environ[SECURITY_MODE_ENV] = mode
    os.environ[DEPLOYMENT_SCENARIO_ENV] = scenario_id
    os.environ["REQUIRE_AGENT_AUTH"] = "true" if scenario["requires_auth"] else "false"
    console.print(
        f"[green]Sicherheitsprofil gesetzt:[/green] {mode} / REQUIRE_AGENT_AUTH={os.environ['REQUIRE_AGENT_AUTH']}"
    )
    _render_persistent_env_hint(
        {
            SECURITY_MODE_ENV: mode,
            DEPLOYMENT_SCENARIO_ENV: scenario_id,
            "REQUIRE_AGENT_AUTH": os.environ["REQUIRE_AGENT_AUTH"],
            VAULT_KEY_FILE_ENV: os.getenv(VAULT_KEY_FILE_ENV, str(DEFAULT_VAULT_KEY_FILE)),
        }
    )
    if key_source.startswith("env:") and mode in {"hardened_local", "remote_secure"}:
        console.print("[yellow]Warnung: Env-Key erkannt. Fuer dieses Szenario Secret-Datei verwenden.[/yellow]")
    if scenario["requires_remote"]:
        console.print("[bold]Remote-Hinweise:[/bold]")
        console.print("  [cyan]-[/cyan] Reverse Proxy + TLS vor KeyRelay setzen")
        console.print("  [cyan]-[/cyan] Nur Relay-Host exponieren, nicht den Agent-Host")
        console.print("  [cyan]-[/cyan] Proxy-User mit engen --scope Werten anlegen")
    else:
        console.print("[bold]Same-Host-Hinweise:[/bold]")
        console.print("  [cyan]-[/cyan] Docker-Socket nicht an Agenten geben")
        console.print("  [cyan]-[/cyan] Keine Secret-Volumes mit dem Agenten teilen")
        console.print("  [cyan]-[/cyan] Getrennte Nutzer/Container fuer Agent und Relay verwenden")

    if Confirm.ask("Admin-User jetzt erstellen?", default=True):
        username = click.prompt("Admin username", default="admin")
        auto_password = Confirm.ask("Sicheres Passwort automatisch generieren?", default=True)
        if auto_password:
            password = secrets.token_urlsafe(18)
            console.print(Panel(password, title="Generiertes Passwort (einmalig anzeigen)", border_style="yellow"))
        else:
            password = click.prompt("Passwort", hide_input=True, confirmation_prompt=True)
        admin_scopes = _collect_user_scopes_interactive(default_scope="all")
        api_key = create_user(username, password, "admin", scopes=admin_scopes)
        if api_key:
            console.print("[bold yellow]Hochrisiko-Hinweis:[/bold yellow] Proxy-Key nur in sicheren Secret-Store uebernehmen.")
            console.print(Panel(api_key, title=f"Proxy API Key fuer {username}", border_style="yellow"))
        else:
            console.print("[yellow]User konnte nicht erstellt werden (evtl. existiert bereits).[/yellow]")

    if Confirm.ask("Bestehende Keys aus Datei importieren?", default=False):
        env_path = click.prompt(".env Datei (leer fuer ueberspringen)", default="", show_default=False).strip()
        json_path = click.prompt("JSON Datei (leer fuer ueberspringen)", default="", show_default=False).strip()
        imported: Dict[str, Dict[str, str]] = {}
        if env_path:
            imported.update(
                {
                    _infer_service_from_env_var(env_var): {"key": value}
                    for env_var, value in _parse_env_file(Path(env_path)).items()
                }
            )
        if json_path:
            imported.update(_load_json_import(Path(json_path)))
        if imported:
            for service, payload in imported.items():
                key_value = payload.pop("key")
                secondary_raw = payload.pop("__secondary_secrets__", "{}")
                try:
                    secondary_secrets = json.loads(secondary_raw) if secondary_raw else {}
                except json.JSONDecodeError:
                    secondary_secrets = {}
                metadata = _collect_service_metadata(service, payload)
                _store_service_key(service, key_value, metadata, secondary_secrets=secondary_secrets)
            console.print(f"[green]Import im Setup abgeschlossen: {len(imported)} Services verarbeitet.[/green]")
        else:
            console.print("[yellow]Keine importierbaren Keys gefunden.[/yellow]")

    if Confirm.ask("Jetzt den ersten Service-Key hinzufuegen?", default=True):
        service = select_service_interactive()
        if service:
            api_key = getpass.getpass(
                f"API key fuer {SERVICES.get(service, {}).get('name', service)}: "
            )
            if api_key:
                format_warning = _validate_key_format(service, api_key)
                if format_warning:
                    console.print(f"[yellow]Hinweis:[/yellow] {format_warning}")
                metadata = _collect_service_metadata(service)
                ok = _store_service_key(service, api_key, metadata)
                if ok:
                    console.print(f"[green]Service-Key fuer '{service}' gespeichert.[/green]")
                    if Confirm.ask("Key jetzt direkt gegen Provider testen?", default=True):
                        status, detail = _validate_service_key_remote(service, api_key, metadata)
                        if status == "valid":
                            console.print(f"[green]Validierung erfolgreich:[/green] {detail}")
                        elif status == "invalid":
                            console.print(f"[red]Validierung fehlgeschlagen:[/red] {detail}")
                        else:
                            console.print(f"[yellow]Validierung nicht eindeutig:[/yellow] {detail}")
                else:
                    console.print("[red]Service-Key konnte nicht gespeichert werden.[/red]")

    if Confirm.ask("Proxy-User fuer Agent jetzt anlegen?", default=True):
        agent_name = click.prompt("Proxy username", default="agent-user")
        auto_pw = Confirm.ask("Sicheres Passwort automatisch generieren?", default=True)
        if auto_pw:
            proxy_password = secrets.token_urlsafe(18)
            console.print(Panel(proxy_password, title="Proxy Passwort (einmalig anzeigen)", border_style="yellow"))
        else:
            proxy_password = click.prompt("Proxy Passwort", hide_input=True, confirmation_prompt=True)
        default_scope = "search" if scenario["requires_remote"] else "llm"
        proxy_scopes = _collect_user_scopes_interactive(default_scope=default_scope)
        proxy_key = create_user(agent_name, proxy_password, "user", scopes=proxy_scopes)
        if proxy_key:
            console.print(Panel(proxy_key, title=f"Proxy API Key fuer {agent_name}", border_style="green"))
            console.print("[bold]Agent-Konfig Beispiel:[/bold]")
            console.print(f"[dim]OPENAI_BASE_URL=http://localhost:8080/openai/v1[/dim]")
            console.print(f"[dim]OPENAI_API_KEY={proxy_key}[/dim]")
        else:
            console.print("[yellow]Proxy-User konnte nicht erstellt werden.[/yellow]")

    console.print("\n[bold green]Setup abgeschlossen.[/bold green]")
    console.print("Empfohlene naechste Befehle:")
    console.print("  [cyan]python3 cli.py start[/cyan]")
    console.print("  [cyan]python3 cli.py doctor[/cyan]")
    console.print("  [cyan]python3 cli.py status[/cyan]")
    docs = SCENARIO_DOCS.get(scenario_id, ["README.md"])
    console.print(f"  [cyan]Doku:[/cyan] {', '.join(docs)}")
    if Confirm.ask("Proxy jetzt starten?", default=False):
        _start_server(host="127.0.0.1", port=8080)


@cli.command(name="add-key", epilog="Beispiel:\n  python3 cli.py add-key --service openai\n  python3 cli.py add-key --interactive")
@click.option("--service", "-s", help="Service name (e.g., openrouter)")
@click.option("--key", "-k", help="API key value")
@click.option("--interactive", "-i", is_flag=True, help="Interactive mode")
@click.option("--search", help="Filter services in interactive mode")
@click.option("--validate/--no-validate", default=True, help="Run provider validation after storing")
def add_key(service, key, interactive, search, validate):
    """Add or update an API key."""
    
    if interactive or (not service and not key):
        service = select_service_interactive(search=search)
        if not service:
            raise click.ClickException("Kein Service ausgewaehlt.")
    
    if not service:
        service = click.prompt("Service name")
    
    if service not in SERVICES:
        console.print(f"[yellow]⚠️  Using custom service:[/yellow] {service}")
    
    # Get API key
    if not key:
        display_name = SERVICES.get(service, {}).get("name", service)
        key = getpass.getpass(f"Enter API key for {display_name}: ")
        
        if not key:
            console.print("[red]❌ Key cannot be empty[/red]")
            return

    format_warning = _validate_key_format(service, key)
    if format_warning:
        console.print(f"[yellow]Hinweis:[/yellow] {format_warning}")

    metadata = _collect_service_metadata(service)
    
    # Save to database
    success = _store_service_key(service, key, metadata)
    
    if success:
        service_info = SERVICES.get(service, {})
        icon = service_info.get("icon", "🔑")
        name = service_info.get("name", service)
        console.print(f"\n[bold green]✅ Added {icon} {name}[/bold green]")
        if validate:
            status, detail = _validate_service_key_remote(service, key, metadata)
            if status == "valid":
                console.print(f"[green]Validierung erfolgreich:[/green] {detail}")
            elif status == "invalid":
                console.print(f"[red]Validierung fehlgeschlagen:[/red] {detail}")
            else:
                console.print(f"[yellow]Validierung Hinweis:[/yellow] {detail}")
        
        # Log the action
        log_request(
            service="cli",
            endpoint="/add-key",
            client_ip="127.0.0.1",
            success=True,
            request_method="POST",
            response_status=200
        )
    else:
        console.print("[red]❌ Failed to save API key[/red]")
        console.print(f"[dim]Tipp:[/dim] pruefe Vault-Key-Quelle und versuche: [cyan]python3 cli.py add-key --service {service}[/cyan]")


@cli.command(name="doctor", epilog="Beispiel:\n  python3 cli.py doctor")
@click.option("--validate-services", is_flag=True, help="Run live provider validation for configured keys")
def doctor(validate_services: bool):
    """Pre-flight configuration validation."""
    checks, ok = run_doctor_checks(validate_services=validate_services)
    render_doctor_results(checks)
    if ok:
        console.print("\n[bold green]Doctor: System ist startbereit.[/bold green]")
    else:
        console.print("\n[bold red]Doctor: Kritische Probleme gefunden.[/bold red]")


@cli.command(name="import-keys", epilog="Beispiel:\n  python3 cli.py import-keys --from-env .env\n  python3 cli.py import-keys --from-json secrets.json")
@click.option("--from-env", type=click.Path(exists=True, path_type=Path), help="Import keys from .env file")
@click.option("--from-json", type=click.Path(exists=True, path_type=Path), help="Import keys from secrets.json file")
@click.option("--from-process-env", is_flag=True, help="Import matching keys from current process environment")
@click.option("--overwrite", is_flag=True, help="Overwrite existing keys")
def import_keys(from_env: Optional[Path], from_json: Optional[Path], from_process_env: bool, overwrite: bool):
    """Bulk-import API keys from .env or JSON files."""
    if not from_env and not from_json and not from_process_env:
        raise click.ClickException("Bitte mindestens --from-env, --from-json oder --from-process-env angeben.")

    imported: Dict[str, Dict[str, str]] = {}
    if from_env:
        env_values = _parse_env_file(from_env)
        for env_var, value in env_values.items():
            imported[_infer_service_from_env_var(env_var)] = {"key": value}
    if from_process_env:
        for env_var, value in os.environ.items():
            if not value:
                continue
            if env_var.startswith("AGENT_VAULT_"):
                continue
            if env_var in ENV_TO_SERVICE or env_var.endswith(("_API_KEY", "_TOKEN", "_PAT")):
                imported[_infer_service_from_env_var(env_var)] = {"key": value}
    if from_json:
        imported.update(_load_json_import(from_json))

    if not imported:
        console.print("[yellow]Keine importierbaren Keys gefunden.[/yellow]")
        return

    preview = Table(title="Import Preview", box=box.ROUNDED)
    preview.add_column("Service", style="cyan")
    preview.add_column("Key")
    preview.add_column("Metadaten")
    for service, payload in sorted(imported.items()):
        missing_metadata = [field for field in _required_metadata_fields(service) if not payload.get(field)]
        metadata_status = "OK" if not missing_metadata else f"Fehlt: {', '.join(missing_metadata)}"
        preview.add_row(service, _mask_value(payload["key"]), metadata_status)
    console.print(preview)

    if not Confirm.ask("Import jetzt ausfuehren?", default=True):
        console.print("[dim]Abgebrochen.[/dim]")
        return

    created = 0
    skipped = 0
    for service, payload in imported.items():
        if get_api_key(service) and not overwrite:
            skipped += 1
            continue
        key_value = payload.pop("key")
        secondary_raw = payload.pop("__secondary_secrets__", "{}")
        try:
            secondary_secrets = json.loads(secondary_raw) if secondary_raw else {}
        except json.JSONDecodeError:
            secondary_secrets = {}
        metadata = _collect_service_metadata(service, payload)
        if _store_service_key(service, key_value, metadata, secondary_secrets=secondary_secrets):
            created += 1
    console.print(f"[green]Import abgeschlossen:[/green] {created} gespeichert, {skipped} uebersprungen.")


@cli.command(name="start", epilog="Beispiel:\n  python3 cli.py start --host 0.0.0.0 --port 8080")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True, type=int)
@click.option("--skip-doctor", is_flag=True, help="Skip pre-flight doctor checks")
def start(host: str, port: int, skip_doctor: bool):
    """Start the KeyRelay proxy server."""
    if not skip_doctor:
        checks, ok = run_doctor_checks()
        render_doctor_results(checks)
        if not ok:
            raise click.ClickException("Doctor checks fehlgeschlagen. Starte mit --skip-doctor nur wenn bewusst.")
    _start_server(host=host, port=port)


@cli.command(name="list-keys", epilog="Beispiel:\n  python3 cli.py list-keys")
@click.option("--show-inactive", is_flag=True, help="Show inactive keys")
def list_keys(show_inactive):
    """📋 List all configured API keys"""
    
    keys = list_api_keys()
    
    if not keys:
        console.print("[yellow]📭 No keys configured[/yellow]")
        console.print("\n[dim]Add your first key:[/dim] [cyan]python cli.py add-key[/cyan]")
        return
    
    # Filter active keys unless --show-inactive
    if not show_inactive:
        keys = [k for k in keys if k.get('is_active', 1)]
    
    console.print(f"\n[bold]📋 Configured Services ({len(keys)})[/bold]\n")
    
    table = Table(
        title="Your API Keys",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    
    table.add_column("Service", style="cyan", min_width=18)
    table.add_column("Name", min_width=20)
    table.add_column("Status", min_width=10)
    table.add_column("Last Updated", min_width=20)
    table.add_column("Details", min_width=25)
    
    for key_data in keys:
        service = key_data['service_name']
        service_info = SERVICES.get(service, {})
        icon = service_info.get("icon", "🔑")
        name = service_info.get("name", service)
        
        status = "[green]✓ Active[/green]" if key_data.get('is_active', 1) else "[red]✗ Inactive[/red]"
        
        details = []
        if key_data.get('cluster'):
            details.append(f"cluster: {key_data['cluster']}")
        if key_data.get('project'):
            details.append(f"project: {key_data['project']}")
        if key_data.get('resource'):
            details.append(f"resource: {key_data['resource']}")
        if key_data.get('cloud_name'):
            details.append(f"cloud: {key_data['cloud_name']}")
        if key_data.get('region'):
            details.append(f"region: {key_data['region']}")
        
        details_str = "\n".join(details) if details else "—"
        
        table.add_row(
            f"{icon} {service}",
            name,
            status,
            key_data.get('updated_at', '—'),
            details_str
        )
    
    console.print(table)
    console.print()


@cli.command(name="remove-key", epilog="Beispiel:\n  python3 cli.py remove-key openai")
@click.argument("service")
@click.confirmation_option(prompt="Are you sure you want to remove this key?")
def remove_key(service):
    """🗑️ Remove an API key"""
    
    service_info = SERVICES.get(service, {})
    icon = service_info.get("icon", "🔑")
    name = service_info.get("name", service)
    
    with console.status(f"[bold red]Removing {name}..."):
        success = remove_api_key(service)
    
    if success:
        console.print(f"[bold green]✅ Removed {icon} {name}[/bold green]")
        log_request(
            service="cli",
            endpoint="/remove-key",
            client_ip="127.0.0.1",
            success=True,
            request_method="DELETE",
            response_status=200
        )
    else:
        console.print(f"[red]❌ Service not found: {service}[/red]")


@cli.command(name="rotate-key", epilog="Beispiel:\n  python3 cli.py rotate-key openai --new-key sk-...")
@click.argument("service")
@click.option("--new-key", "-k", help="New API key value")
def rotate_key(service, new_key):
    """🔄 Rotate (update) an API key"""
    
    service_info = SERVICES.get(service, {})
    icon = service_info.get("icon", "🔑")
    name = service_info.get("name", service)
    
    if not new_key:
        new_key = getpass.getpass(f"Enter new API key for {name}: ")
    
    if not new_key:
        console.print("[red]❌ Key cannot be empty[/red]")
        return
    
    with console.status(f"[bold yellow]Rotating {name} key..."):
        success = rotate_api_key(service, new_key)
    
    if success:
        console.print(f"[bold green]✅ Rotated {icon} {name} key[/bold green]")
        log_request(
            service="cli",
            endpoint="/rotate-key",
            client_ip="127.0.0.1",
            success=True,
            request_method="PUT",
            response_status=200
        )
    else:
        console.print(f"[red]❌ Failed to rotate key for {service}[/red]")


@cli.command(name="audit-logs", epilog="Beispiel:\n  python3 cli.py audit-logs --limit 20\n  python3 cli.py audit-logs --stats")
@click.option("--service", "-s", help="Filter by service")
@click.option("--limit", "-n", default=50, help="Number of entries to show")
@click.option("--stats", is_flag=True, help="Show statistics only")
def audit_logs(service, limit, stats):
    """📜 View audit logs"""
    
    if stats:
        stats_data = get_audit_stats()
        
        console.print("\n[bold]📊 Audit Statistics[/bold]\n")
        
        table = Table(box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value")
        
        table.add_row("Total Requests", str(stats_data['total_requests']))
        table.add_row("Successful", f"[green]{stats_data['successful']}[/green]")
        table.add_row("Failed", f"[red]{stats_data['failed']}[/red]")
        
        console.print(table)
        
        if stats_data['by_service']:
            console.print("\n[bold]By Service:[/bold]")
            svc_table = Table(box=box.ROUNDED)
            svc_table.add_column("Service", style="cyan")
            svc_table.add_column("Requests")
            
            for svc, count in sorted(stats_data['by_service'].items(), key=lambda x: -x[1]):
                svc_table.add_row(svc, str(count))
            
            console.print(svc_table)
        return
    
    logs = get_audit_logs(service=service, limit=limit)
    
    if not logs:
        console.print("[yellow]📭 No audit logs found[/yellow]")
        return
    
    console.print(f"\n[bold]📜 Audit Logs[/bold] [dim](last {len(logs)} entries)[/dim]\n")
    
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Timestamp", style="dim", min_width=20)
    table.add_column("Service", style="cyan", min_width=15)
    table.add_column("Endpoint", min_width=25)
    table.add_column("Method", min_width=8)
    table.add_column("Status", min_width=8)
    table.add_column("Client IP", min_width=15)
    table.add_column("Success", min_width=8)
    
    for log in logs:
        success_str = "[green]✓[/green]" if log.get('success') else "[red]✗[/red]"
        status_str = str(log.get('response_status', '—'))
        if log.get('response_status'):
            if log['response_status'] < 400:
                status_str = f"[green]{status_str}[/green]"
            else:
                status_str = f"[red]{status_str}[/red]"
        
        table.add_row(
            log.get('timestamp', '—'),
            log.get('service', '—'),
            log.get('endpoint', '—')[:25],
            log.get('request_method', '—'),
            status_str,
            log.get('client_ip', '—'),
            success_str
        )
    
    console.print(table)
    console.print()


# User Management Commands

@cli.command(name="user-create", epilog="Beispiel:\n  python3 cli.py user-create agent-prod --role admin --auto-password")
@click.argument("username")
@click.option("--role", default="user", type=click.Choice(["admin", "user"]), help="User role")
@click.option("--password", "-p", help="User password", hide_input=True, confirmation_prompt=True)
@click.option("--auto-password", is_flag=True, help="Generate secure password automatically")
@click.option("--scope", "scopes", multiple=True, help="Allowed services, comma-separated or repeated (default: *)")
@click.option("--scope-preset", type=click.Choice(["llm", "search", "git", "all"]), help="Scope preset")
@click.option("--interactive-scopes", is_flag=True, help="Choose scopes interactively")
def user_create(username, role, password, auto_password, scopes, scope_preset, interactive_scopes):
    """Create a new user."""
    if auto_password:
        password = secrets.token_urlsafe(18)
        console.print(Panel(password, title="Generiertes Passwort (einmalig anzeigen)", border_style="yellow"))
    if not password:
        password = click.prompt("User password", hide_input=True, confirmation_prompt=True)
    
    if interactive_scopes:
        default_scope = scope_preset or ("all" if role == "admin" else "llm")
        normalized_scopes = _collect_user_scopes_interactive(default_scope=default_scope)
    elif scope_preset:
        normalized_scopes = list(SCOPE_PRESETS.get(scope_preset, DEFAULT_SCOPES))
    else:
        normalized_scopes = _normalize_scope_values(scopes)
    with console.status("[bold green]Creating user..."):
        api_key = create_user(username, password, role, scopes=normalized_scopes)
    
    if api_key:
        console.print(f"\n[bold green]✅ User created successfully![/bold green]")
        console.print(f"[cyan]Username:[/cyan] {username}")
        console.print(f"[cyan]Role:[/cyan] {role}")
        console.print(f"[cyan]Scopes:[/cyan] {', '.join(normalized_scopes)}")
        console.print("[bold yellow]Hochrisiko:[/bold yellow] Klartext-Key nur in sicherem Kontext verarbeiten.")
        console.print(f"\n[bold yellow]🔑 API Key (save this!):[/bold yellow]")
        console.print(Panel(api_key, border_style="yellow"))
        console.print("[dim]This key is required to access the proxy.[/dim]")
        if _is_reveal_enabled():
            try:
                import pyperclip  # type: ignore
                pyperclip.copy(api_key)
                console.print("[dim]API key wurde in die Zwischenablage kopiert.[/dim]")
            except Exception:
                console.print("[dim]Zwischenablage nicht verfuegbar - key bitte manuell speichern.[/dim]")
        else:
            console.print(
                f"[dim]Clipboard deaktiviert (setze {ALLOW_SECRET_REVEAL_ENV}=true fuer explizite Freigabe).[/dim]"
            )
    else:
        console.print(f"[red]❌ Failed to create user (may already exist)[/red]")


@cli.command(name="user-list", epilog="Beispiel:\n  python3 cli.py user-list")
def user_list():
    """👥 List all users"""
    
    users = list_users()
    
    if not users:
        console.print("[yellow]📭 No users found[/yellow]")
        return
    
    console.print(f"\n[bold]👥 Users ({len(users)})[/bold]\n")
    
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Username", style="cyan")
    table.add_column("Role", min_width=10)
    table.add_column("Scopes", min_width=20)
    table.add_column("Created", min_width=20)
    table.add_column("Last Access", min_width=20)
    table.add_column("Status", min_width=10)
    
    for user in users:
        role_color = "red" if user['role'] == 'admin' else "blue"
        status = "[green]✓ Active[/green]" if user.get('is_active', 1) else "[red]✗ Inactive[/red]"
        
        table.add_row(
            user['username'],
            f"[{role_color}]{user['role']}[/{role_color}]",
            ", ".join(user.get("scopes", ["*"])),
            user.get('created_at', '—'),
            user.get('last_access', 'Never'),
            status
        )
    
    console.print(table)
    console.print()


@cli.command(name="user-delete", epilog="Beispiel:\n  python3 cli.py user-delete agent-prod")
@click.argument("username")
@click.confirmation_option(prompt="Are you sure you want to delete this user?")
def user_delete(username):
    """🗑️ Delete a user"""
    
    with console.status(f"[bold red]Deleting {username}..."):
        success = delete_user(username)
    
    if success:
        console.print(f"[bold green]✅ Deleted user {username}[/bold green]")
    else:
        console.print(f"[red]❌ User not found: {username}[/red]")


@cli.command(name="user-verify", epilog="Beispiel:\n  python3 cli.py user-verify --api-key <key>")
@click.option("--api-key", "-k", help="API key to verify")
def user_verify(api_key):
    """🔍 Verify an API key"""
    
    if not api_key:
        api_key = getpass.getpass("Enter API key to verify: ")
    
    user = verify_api_key(api_key)
    
    if user:
        console.print(f"\n[bold green]✅ Valid API key[/bold green]")
        console.print(f"[cyan]Username:[/cyan] {user['username']}")
        console.print(f"[cyan]Role:[/cyan] {user['role']}")
        console.print(f"[cyan]Scopes:[/cyan] {', '.join(user.get('scopes', ['*']))}")
    else:
        console.print("[red]❌ Invalid API key[/red]")


# Utility Commands

@cli.command(name="export-env", epilog="Beispiel:\n  python3 cli.py export-env\n  python3 cli.py export-env --reveal")
@click.option("--reveal", is_flag=True, help="Show full key values (default: masked)")
def export_env(reveal):
    """Export keys as environment variable mappings (masked by default)."""
    
    keys = list_api_keys()
    
    if not keys:
        console.print("[yellow]No keys to export[/yellow]")
        return
    
    env_mappings = {
        "openrouter": "OPENROUTER_API_KEY",
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "groq": "GROQ_API_KEY",
        "cohere": "COHERE_API_KEY",
        "mistral": "MISTRAL_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "pinecone": "PINECONE_API_KEY",
        "brave": "BRAVE_API_KEY",
        "github": "GITHUB_PAT",
        "slack": "SLACK_TOKEN",
        "langsmith": "LANGSMITH_API_KEY",
        "notion": "NOTION_API_KEY",
        "airtable": "AIRTABLE_API_KEY",
        "twilio": "TWILIO_AUTH_TOKEN",
        "sendgrid": "SENDGRID_API_KEY",
    }
    
    if reveal:
        if not _is_reveal_enabled():
            console.print(
                f"[red]Klartext-Export blockiert.[/red] Setze {ALLOW_SECRET_REVEAL_ENV}=true fuer bewusste Freigabe."
            )
            return
        console.print("[bold yellow]WARNUNG:[/bold yellow] Keys werden im Klartext angezeigt.")
        if not Confirm.ask("Fortfahren?", default=False):
            return
    
    console.print("\n[bold]Environment Variables Export[/bold]\n")
    
    for key_data in keys:
        service = key_data['service_name']
        api_key = get_api_key(service)
        if api_key:
            env_var = env_mappings.get(service, f"{service.upper()}_API_KEY")
            if reveal:
                console.print(f"[green]{env_var}[/green]={api_key}")
            else:
                console.print(f"[green]{env_var}[/green]=[dim]{_mask_value(api_key)}[/dim]")
    
    console.print()


@cli.command(name="status", epilog="Beispiel:\n  python3 cli.py status")
def status():
    """ℹ️ Show vault status"""
    
    print_banner()
    
    if not APP_DIR.exists():
        console.print("[yellow]⚠️  Vault not initialized[/yellow]")
        console.print("\n[dim]Run:[/dim] [cyan]python cli.py init[/cyan]")
        return
    
    # Count keys
    keys = list_api_keys()
    users = list_users()
    stats = get_audit_stats()
    
    # Get file sizes
    db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    
    console.print("\n[bold]Vault Status[/bold]\n")
    
    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    
    table.add_row("Location", str(APP_DIR))
    table.add_row("Database", str(DB_PATH))
    table.add_row("Database size", f"{db_size / 1024:.1f} KB")
    table.add_row("API Keys stored", str(len(keys)))
    table.add_row("Users", str(len(users)))
    table.add_row("Total requests", str(stats['total_requests']))
    table.add_row("Encryption", "Fernet (AES-128-CBC + HMAC)")
    table.add_row("Security mode", get_security_mode())
    table.add_row("Deployment scenario", os.getenv(DEPLOYMENT_SCENARIO_ENV, "not set"))
    try:
        key_source = get_vault_key_source()
        key_source_status = key_source
        if key_source.startswith("env:"):
            key_source_status += " [yellow](schwaecher als Secret-Datei)[/yellow]"
    except Exception:
        key_source_status = "[red]Not configured[/red]"
    table.add_row("Vault key source", key_source_status)
    table.add_row("Secret reveal", "enabled" if _is_reveal_enabled() else "disabled")
    
    console.print(table)
    
    if keys:
        console.print("\n[bold]Configured Services:[/bold]")
        services_str = ", ".join([k['service_name'] for k in keys[:10]])
        if len(keys) > 10:
            services_str += f" and {len(keys) - 10} more"
        console.print(f"[dim]{services_str}[/dim]")
    
    console.print()


@cli.command(name="get-key", epilog="Beispiel:\n  python3 cli.py get-key openai")
@click.argument("service")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def get_key(service, yes):
    """Retrieve a specific API key (decrypted). Requires confirmation."""
    if not _is_reveal_enabled():
        console.print(
            f"[red]Klartext-Anzeige blockiert.[/red] Setze {ALLOW_SECRET_REVEAL_ENV}=true fuer bewusste Freigabe."
        )
        return
    
    if not yes:
        console.print("[bold yellow]WARNUNG:[/bold yellow] Dieser Befehl zeigt den entschluesselten API-Key im Terminal.")
        console.print("[dim]Sicherstellen, dass kein Bildschirmrecording/Logging aktiv ist.[/dim]")
        if not Confirm.ask("Key wirklich anzeigen?", default=False):
            console.print("[dim]Abgebrochen.[/dim]")
            return
    
    key = get_api_key(service)
    
    if key:
        service_info = SERVICES.get(service, {})
        icon = service_info.get("icon", "🔑")
        name = service_info.get("name", service)
        console.print(f"\n[bold]{icon} {name} API Key:[/bold]")
        console.print(Panel(key, border_style="green"))
        
        log_request(
            service="cli",
            endpoint="/get-key",
            client_ip="127.0.0.1",
            success=True,
            request_method="GET",
            response_status=200
        )
    else:
        console.print(f"[red]No key found for {service}[/red]")
        console.print(f"[dim]Tipp:[/dim] [cyan]python3 cli.py add-key --service {service}[/cyan]")


@cli.command(name="help", epilog="Beispiel:\n  python3 cli.py help\n  python3 cli.py add-key --help")
@click.pass_context
def help_command(ctx):
    """Show a command overview and examples."""
    console.print("[bold]KeyRelay CLI command overview[/bold]\n")
    commands = [
        ("setup", "Primarer Happy Path inkl. Szenario-Auswahl"),
        ("doctor", "Vollstaendiger Konfigurationscheck"),
        ("start", "Proxy starten (inkl. Pre-Checks)"),
        ("add-key", "Service-Key speichern/validieren"),
        ("import-keys", "Bulk-Import aus .env / JSON / Prozess-Env"),
        ("user-create", "Proxy-User anlegen (Scopes/Presets)"),
        ("status", "Aktuellen Vault-Status anzeigen"),
    ]
    table = Table(box=box.ROUNDED)
    table.add_column("Command", style="cyan")
    table.add_column("Beschreibung")
    for command, description in commands:
        table.add_row(f"python3 cli.py {command}", description)
    console.print(table)
    console.print("\n[dim]Fuer Details: python3 cli.py <command> --help[/dim]")


if __name__ == "__main__":
    cli()