#!/usr/bin/env python3
"""
KeyRelay CLI v2 - Enhanced key management and onboarding.
"""

import json
import getpass
import os
import secrets
import subprocess
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import click
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
)
from cryptography.fernet import Fernet

console = Console()

# Version constant
VERSION = "2.0.0"

# App directory configuration
APP_DIR = Path(
    os.getenv("AGENT_VAULT_APP_DIR", str(Path.home() / ".agent-vault"))
).expanduser()
DB_PATH = APP_DIR / "vault.db"
KEY_FILE = APP_DIR / ".key"

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
║   🔐  [bold cyan]KEYRELAY v2.0[/bold cyan] - Secure API Key Relay            ║
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


def _generate_fernet_key() -> str:
    return Fernet.generate_key().decode()


def _collect_service_metadata(service: str) -> Dict[str, str]:
    metadata: Dict[str, str] = {}
    if service in ["azure_openai"]:
        metadata["resource"] = click.prompt("Resource name (optional)", default="", show_default=False) or None
    elif service in ["weaviate", "qdrant", "milvus"]:
        metadata["cluster"] = click.prompt("Cluster name (optional)", default="", show_default=False) or None
    elif service == "supabase":
        metadata["project"] = click.prompt("Project ID (optional)", default="", show_default=False) or None
    elif service == "cloudinary":
        metadata["cloud_name"] = click.prompt("Cloud name (optional)", default="", show_default=False) or None
    elif service == "twilio":
        metadata["account_sid"] = click.prompt("Account SID (optional)", default="", show_default=False) or None
    elif service in ["aws", "aws_bedrock"]:
        metadata["region"] = click.prompt("AWS region (optional)", default="us-east-1")
    elif service in ["auth0", "okta"]:
        metadata["domain"] = click.prompt("Domain (optional, without protocol)", default="", show_default=False) or None
    elif service == "shopify":
        metadata["shop"] = click.prompt("Shop name (optional, without .myshopify.com)", default="", show_default=False) or None
    return {k: v for k, v in metadata.items() if v is not None}


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


def run_doctor_checks() -> Tuple[List[Dict[str, str]], bool]:
    """Run setup and security checks used by doctor/start commands."""
    checks: List[Dict[str, str]] = []
    success = True

    key = os.getenv("AGENT_VAULT_KEY", "").strip()
    if not key:
        checks.append({"name": "AGENT_VAULT_KEY", "status": "fail", "detail": "Nicht gesetzt"})
        success = False
    else:
        try:
            _ = get_encryption_key()
            checks.append({"name": "AGENT_VAULT_KEY", "status": "pass", "detail": f"Gesetzt ({len(key)} Zeichen)"})
        except Exception as exc:
            checks.append({"name": "AGENT_VAULT_KEY", "status": "fail", "detail": f"Ungueltig: {exc}"})
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
    except Exception as exc:
        checks.append({"name": "Proxy Users", "status": "fail", "detail": str(exc)})
        success = False

    for dependency in ["fastapi", "uvicorn", "httpx", "cryptography", "rich", "click"]:
        try:
            __import__(dependency)
            checks.append({"name": f"Dependency '{dependency}'", "status": "pass", "detail": "OK"})
        except Exception:
            checks.append({"name": f"Dependency '{dependency}'", "status": "fail", "detail": "Nicht installiert"})
            success = False

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
        key_value = data.get("api_key") or data.get("token") or data.get("pat") or data.get("secret_key")
        if not key_value:
            continue
        metadata = {k: v for k, v in data.items() if k not in {"api_key", "token", "pat", "secret_key"} and v}
        normalized[service] = {"key": key_value, **metadata}
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
@click.version_option(version="2.0.0", prog_name="keyrelay")
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

    key = os.getenv("AGENT_VAULT_KEY", "").strip()
    if not key:
        generated = _generate_fernet_key()
        console.print("[yellow]AGENT_VAULT_KEY ist nicht gesetzt.[/yellow]")
        console.print(Panel(generated, title="Generierter Fernet Key", border_style="yellow"))
        if Confirm.ask("Diesen Key fuer diese Setup-Session verwenden?", default=True):
            os.environ["AGENT_VAULT_KEY"] = generated
            console.print("[green]Key fuer diese Session gesetzt.[/green]")
            console.print("[dim]Persistent setzen (z.B. shell rc / .env): export AGENT_VAULT_KEY='<key>'[/dim]")
        else:
            raise click.ClickException("Setup abgebrochen. Setze AGENT_VAULT_KEY und starte erneut.")

    if DB_PATH.exists():
        console.print("[green]Vorhandene Vault-DB erkannt.[/green]")
    else:
        with console.status("[bold green]Initialisiere Vault..."):
            init_database()
        console.print("[green]Vault initialisiert.[/green]")

    mode = click.prompt(
        "Modus waehlen",
        type=click.Choice(["production", "development"], case_sensitive=False),
        default="production",
    ).lower()
    if mode == "development":
        console.print("[yellow]Development-Modus: setze REQUIRE_AGENT_AUTH=false fuer lokale Tests.[/yellow]")
    else:
        console.print("[green]Production-Modus: REQUIRE_AGENT_AUTH sollte true bleiben.[/green]")
        if Confirm.ask("Admin-User jetzt erstellen?", default=True):
            username = click.prompt("Admin username", default="admin")
            auto_password = Confirm.ask("Sicheres Passwort automatisch generieren?", default=True)
            if auto_password:
                password = secrets.token_urlsafe(18)
                console.print(Panel(password, title="Generiertes Passwort (einmalig anzeigen)", border_style="yellow"))
            else:
                password = click.prompt("Passwort", hide_input=True, confirmation_prompt=True)
            api_key = create_user(username, password, "admin")
            if api_key:
                console.print(Panel(api_key, title=f"Proxy API Key fuer {username}", border_style="yellow"))
            else:
                console.print("[yellow]User konnte nicht erstellt werden (evtl. existiert bereits).[/yellow]")

    if Confirm.ask("Jetzt den ersten Service-Key hinzufuegen?", default=True):
        service = select_service_interactive()
        if service:
            api_key = getpass.getpass(
                f"API key fuer {SERVICES.get(service, {}).get('name', service)}: "
            )
            if api_key:
                metadata = _collect_service_metadata(service)
                ok = add_api_key(service, api_key, metadata if metadata else None)
                if ok and metadata:
                    set_service_metadata(service, **metadata)
                if ok:
                    console.print(f"[green]Service-Key fuer '{service}' gespeichert.[/green]")
                else:
                    console.print("[red]Service-Key konnte nicht gespeichert werden.[/red]")

    console.print("\n[bold green]Setup abgeschlossen.[/bold green]")
    console.print("Empfohlene naechste Befehle:")
    console.print("  [cyan]python3 cli.py doctor[/cyan]")
    console.print("  [cyan]python3 cli.py status[/cyan]")
    if Confirm.ask("Proxy jetzt starten?", default=False):
        _start_server(host="127.0.0.1", port=8080)


@cli.command(name="add-key", epilog="Beispiel:\n  python3 cli.py add-key --service openai\n  python3 cli.py add-key --interactive")
@click.option("--service", "-s", help="Service name (e.g., openrouter)")
@click.option("--key", "-k", help="API key value")
@click.option("--interactive", "-i", is_flag=True, help="Interactive mode")
@click.option("--search", help="Filter services in interactive mode")
def add_key(service, key, interactive, search):
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
    
    metadata = _collect_service_metadata(service)
    
    # Save to database
    with console.status("[bold green]Saving API key..."):
        success = add_api_key(service, key, metadata if metadata else None)
    
    if success:
        # Save metadata to separate table if exists
        if metadata:
            set_service_metadata(service, **metadata)
        
        service_info = SERVICES.get(service, {})
        icon = service_info.get("icon", "🔑")
        name = service_info.get("name", service)
        console.print(f"\n[bold green]✅ Added {icon} {name}[/bold green]")
        
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
        console.print(f"[dim]Tipp:[/dim] pruefe AGENT_VAULT_KEY und versuche: [cyan]python3 cli.py add-key --service {service}[/cyan]")


@cli.command(name="doctor", epilog="Beispiel:\n  python3 cli.py doctor")
def doctor():
    """Pre-flight configuration validation."""
    checks, ok = run_doctor_checks()
    render_doctor_results(checks)
    if ok:
        console.print("\n[bold green]Doctor: System ist startbereit.[/bold green]")
    else:
        console.print("\n[bold red]Doctor: Kritische Probleme gefunden.[/bold red]")


@cli.command(name="import-keys", epilog="Beispiel:\n  python3 cli.py import-keys --from-env .env\n  python3 cli.py import-keys --from-json secrets.json")
@click.option("--from-env", type=click.Path(exists=True, path_type=Path), help="Import keys from .env file")
@click.option("--from-json", type=click.Path(exists=True, path_type=Path), help="Import keys from secrets.json file")
@click.option("--overwrite", is_flag=True, help="Overwrite existing keys")
def import_keys(from_env: Optional[Path], from_json: Optional[Path], overwrite: bool):
    """Bulk-import API keys from .env or JSON files."""
    if not from_env and not from_json:
        raise click.ClickException("Bitte mindestens --from-env oder --from-json angeben.")

    imported: Dict[str, Dict[str, str]] = {}
    if from_env:
        env_values = _parse_env_file(from_env)
        for env_var, value in env_values.items():
            imported[_infer_service_from_env_var(env_var)] = {"key": value}
    if from_json:
        imported.update(_load_json_import(from_json))

    if not imported:
        console.print("[yellow]Keine importierbaren Keys gefunden.[/yellow]")
        return

    preview = Table(title="Import Preview", box=box.ROUNDED)
    preview.add_column("Service", style="cyan")
    preview.add_column("Key")
    for service, payload in sorted(imported.items()):
        preview.add_row(service, _mask_value(payload["key"]))
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
        metadata = payload or None
        if add_api_key(service, key_value, metadata):
            if metadata:
                set_service_metadata(service, **metadata)
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
def user_create(username, role, password, auto_password):
    """Create a new user."""
    if auto_password:
        password = secrets.token_urlsafe(18)
        console.print(Panel(password, title="Generiertes Passwort (einmalig anzeigen)", border_style="yellow"))
    if not password:
        password = click.prompt("User password", hide_input=True, confirmation_prompt=True)
    
    with console.status("[bold green]Creating user..."):
        api_key = create_user(username, password, role)
    
    if api_key:
        console.print(f"\n[bold green]✅ User created successfully![/bold green]")
        console.print(f"[cyan]Username:[/cyan] {username}")
        console.print(f"[cyan]Role:[/cyan] {role}")
        console.print(f"\n[bold yellow]🔑 API Key (save this!):[/bold yellow]")
        console.print(Panel(api_key, border_style="yellow"))
        console.print("[dim]This key is required to access the proxy.[/dim]")
        try:
            import pyperclip  # type: ignore
            pyperclip.copy(api_key)
            console.print("[dim]API key wurde in die Zwischenablage kopiert.[/dim]")
        except Exception:
            console.print("[dim]Zwischenablage nicht verfuegbar - key bitte manuell speichern.[/dim]")
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
    table.add_column("Created", min_width=20)
    table.add_column("Last Access", min_width=20)
    table.add_column("Status", min_width=10)
    
    for user in users:
        role_color = "red" if user['role'] == 'admin' else "blue"
        status = "[green]✓ Active[/green]" if user.get('is_active', 1) else "[red]✗ Inactive[/red]"
        
        table.add_row(
            user['username'],
            f"[{role_color}]{user['role']}[/{role_color}]",
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
    else:
        console.print("[red]❌ Invalid API key[/red]")


# Utility Commands

@cli.command(name="export-env", epilog="Beispiel:\n  python3 cli.py export-env")
def export_env():
    """📤 Export keys to environment variable format"""
    
    keys = list_api_keys()
    
    if not keys:
        console.print("[yellow]📭 No keys to export[/yellow]")
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
    
    console.print("\n[bold]📤 Environment Variables Export[/bold]\n")
    console.print("[dim]# Copy these to your .env file:[/dim]\n")
    
    for key_data in keys:
        service = key_data['service_name']
        api_key = get_api_key(service)
        if api_key:
            env_var = env_mappings.get(service, f"{service.upper()}_API_KEY")
            masked = api_key[:4] + "*" * (len(api_key) - 8) + api_key[-4:] if len(api_key) > 8 else "****"
            console.print(f"[green]{env_var}[/green]=[dim]{masked}[/dim]")
    
    console.print("\n[dim]# End of export[/dim]\n")


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
    env_key = os.getenv("AGENT_VAULT_KEY", "")
    if env_key:
        env_key_status = f"Set ({len(env_key)} Zeichen)"
    else:
        env_key_status = "[red]Not set[/red]"
    table.add_row("Environment Key", env_key_status)
    
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
def get_key(service):
    """🔑 Retrieve a specific API key (decrypted)"""
    
    key = get_api_key(service)
    
    if key:
        service_info = SERVICES.get(service, {})
        icon = service_info.get("icon", "🔑")
        name = service_info.get("name", service)
        console.print(f"\n[bold]{icon} {name} API Key:[/bold]")
        console.print(Panel(key, border_style="green"))
        
        # Log this sensitive access
        log_request(
            service="cli",
            endpoint="/get-key",
            client_ip="127.0.0.1",
            success=True,
            request_method="GET",
            response_status=200
        )
    else:
        console.print(f"[red]❌ No key found for {service}[/red]")
        console.print(f"[dim]Tipp:[/dim] [cyan]python3 cli.py add-key --service {service}[/cyan]")


@cli.command(name="help", epilog="Beispiel:\n  python3 cli.py help\n  python3 cli.py add-key --help")
@click.pass_context
def help_command(ctx):
    """Show a command overview and examples."""
    console.print("[bold]KeyRelay CLI command overview[/bold]\n")
    commands = [
        ("setup", "Gefuehrtes Erst-Setup"),
        ("doctor", "Vollstaendiger Konfigurationscheck"),
        ("start", "Proxy starten (inkl. Pre-Checks)"),
        ("add-key", "Service-Key speichern/aktualisieren"),
        ("import-keys", "Bulk-Import aus .env / JSON"),
        ("user-create", "Proxy-User anlegen"),
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