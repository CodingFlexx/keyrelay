#!/usr/bin/env python3
"""
Agent Vault CLI - Manage API keys and configuration

A polished, interactive CLI for managing your Agent Vault.
"""

import base64
import getpass
import hashlib
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from cryptography.fernet import Fernet
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

app = typer.Typer(
    name="agent-vault",
    help="🔐 Secure API Key Management for AI Agents",
    rich_markup_mode="rich"
)
console = Console()

APP_DIR = Path.home() / ".agent-vault"
DB_PATH = APP_DIR / "vault.db"
KEY_FILE = APP_DIR / ".master_key"
AUDIT_LOG = APP_DIR / "audit.log"

# Service definitions with icons and descriptions
SERVICES = {
    "openrouter": ("🌐", "OpenRouter", "Universal LLM API gateway"),
    "openai": ("🤖", "OpenAI", "GPT models and embeddings"),
    "anthropic": ("🧠", "Anthropic", "Claude AI models"),
    "gemini": ("💎", "Google Gemini", "Google AI models"),
    "groq": ("⚡", "Groq", "Fast inference API"),
    "cohere": ("📝", "Cohere", "Text embeddings and generation"),
    "mistral": ("🌪️", "Mistral AI", "Open source LLMs"),
    "deepseek": ("🔍", "DeepSeek", "Chinese LLM provider"),
    "azure_openai": ("☁️", "Azure OpenAI", "Microsoft Azure AI"),
    "aws_bedrock": ("📦", "AWS Bedrock", "Amazon AI platform"),
    "pinecone": ("🌲", "Pinecone", "Vector database"),
    "weaviate": ("🔮", "Weaviate", "AI-native vector DB"),
    "qdrant": ("🎯", "Qdrant", "Vector similarity search"),
    "chroma": ("🎨", "Chroma", "Embedding database"),
    "milvus": ("🦅", "Milvus", "Distributed vector DB"),
    "brave": ("🦁", "Brave Search", "Privacy-focused search"),
    "serpapi": ("🔎", "SerpAPI", "Google search API"),
    "tavily": ("📊", "Tavily", "AI search engine"),
    "exa": ("🔬", "Exa", "Neural search"),
    "perplexity": ("❓", "Perplexity", "AI answer engine"),
    "github": ("🐙", "GitHub", "Code repository"),
    "gitlab": ("🦊", "GitLab", "DevOps platform"),
    "bitbucket": ("🪣", "Bitbucket", "Git repository hosting"),
    "supabase": ("⚡", "Supabase", "Firebase alternative"),
    "firebase": ("🔥", "Firebase", "Google app platform"),
    "slack": ("💬", "Slack", "Team messaging"),
    "discord": ("🎮", "Discord", "Community chat"),
    "telegram": ("✈️", "Telegram", "Secure messaging"),
    "twilio": ("📞", "Twilio", "Communication APIs"),
    "sendgrid": ("📧", "SendGrid", "Email delivery"),
    "langsmith": ("🔧", "LangSmith", "LLM observability"),
    "langfuse": ("📈", "Langfuse", "LLM analytics"),
    "weights_biases": ("🏋️", "Weights & Biases", "ML experiment tracking"),
    "arize": ("📊", "Arize", "ML observability"),
    "replicate": ("🔄", "Replicate", "ML model hosting"),
    "stability": ("🎭", "Stability AI", "Image generation"),
    "cloudinary": ("☁️", "Cloudinary", "Media management"),
    "huggingface": ("🤗", "Hugging Face", "ML community"),
    "assemblyai": ("🎤", "AssemblyAI", "Speech recognition"),
    "elevenlabs": ("🗣️", "ElevenLabs", "Voice synthesis"),
}


def print_banner():
    """Print welcome banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   🔐  [bold cyan]AGENT VAULT[/bold cyan] - Secure API Key Management      ║
    ║                                                          ║
    ║   Your API keys, encrypted and managed with care.        ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, border_style="cyan", box=box.DOUBLE))


def log_action(action: str, service: str = "", details: str = ""):
    """Log action to audit log."""
    timestamp = datetime.now().isoformat()
    user = getpass.getuser()
    entry = f"[{timestamp}] [{user}] {action}"
    if service:
        entry += f" service={service}"
    if details:
        entry += f" {details}"
    entry += "\n"
    
    with open(AUDIT_LOG, "a") as f:
        f.write(entry)


def get_cipher() -> Fernet:
    """Get cipher instance."""
    if not KEY_FILE.exists():
        console.print("[bold red]❌ Vault not initialized![/bold red]")
        console.print("\n[dim]Run:[/dim] [cyan]./cli.py init[/cyan]")
        raise typer.Exit(1)
    
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    
    return Fernet(key)


@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Force reinitialization (deletes existing keys)")
):
    """🔐 Initialize the vault with a master password."""
    print_banner()
    
    if APP_DIR.exists() and not force:
        console.print(f"[yellow]⚠️  Vault already exists at:[/yellow] {APP_DIR}")
        if not Confirm.ask("Reinitialize? This will [bold red]DELETE[/bold red] all existing keys!", default=False):
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit()
    
    # Create directory
    APP_DIR.mkdir(mode=0o700, exist_ok=True)
    
    console.print("\n[bold]Set your master password[/bold]")
    console.print("[dim]This password protects all your API keys.[/dim]\n")
    
    while True:
        password = getpass.getpass("Master password: ")
        if len(password) < 8:
            console.print("[red]❌ Password must be at least 8 characters[/red]")
            continue
        
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            console.print("[red]❌ Passwords don't match[/red]")
            continue
        
        break
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing vault...", total=None)
        
        # Generate encryption key
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'agent-vault-salt', 100000)
        fernet_key = base64.urlsafe_b64encode(key)
        
        # Save key file
        with open(KEY_FILE, 'wb') as f:
            f.write(fernet_key)
        os.chmod(KEY_FILE, 0o600)
        
        # Create database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                service TEXT PRIMARY KEY,
                key_value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS service_metadata (
                service TEXT PRIMARY KEY,
                cluster TEXT,
                project TEXT,
                resource TEXT,
                cloud_name TEXT,
                account_sid TEXT,
                FOREIGN KEY (service) REFERENCES api_keys(service)
            )
        ''')
        
        conn.commit()
        conn.close()
        os.chmod(DB_PATH, 0o600)
        
        # Initialize audit log
        with open(AUDIT_LOG, "w") as f:
            f.write(f"[{datetime.now().isoformat()}] [system] Vault initialized\n")
        os.chmod(AUDIT_LOG, 0o600)
        
        progress.update(task, completed=True)
    
    console.print("\n[bold green]✅ Vault initialized successfully![/bold green]")
    console.print(f"\n[dim]Location:[/dim] {APP_DIR}")
    console.print(f"[dim]Database:[/dim] {DB_PATH}")
    
    console.print("\n[bold]Next steps:[/bold]")
    console.print("  [cyan]./cli.py add[/cyan]       # Add your first API key")
    console.print("  [cyan]./cli.py list[/cyan]      # View all services")


@app.command()
def add(
    service: Optional[str] = typer.Argument(None, help="Service name (e.g., openrouter)"),
    key: Optional[str] = typer.Argument(None, help="API key value")
):
    """➕ Add or update an API key."""
    cipher = get_cipher()
    
    # Interactive mode if no arguments
    if not service:
        console.print("\n[bold]Available services:[/bold]\n")
        
        # Show services in a grid
        table = Table(show_header=False, box=None, padding=(0, 2))
        services_list = list(SERVICES.items())
        
        for i in range(0, len(services_list), 3):
            row = []
            for j in range(3):
                if i + j < len(services_list):
                    key_name, (icon, name, desc) = services_list[i + j]
                    row.append(f"{icon} [cyan]{key_name}[/cyan] - {name}")
            if row:
                table.add_row(*row)
        
        console.print(table)
        console.print("\n[dim]Or type a custom service name[/dim]\n")
        
        service = Prompt.ask("Service", choices=list(SERVICES.keys()) + ["custom"])
        if service == "custom":
            service = Prompt.ask("Custom service name").lower().replace(" ", "_")
    
    if service not in SERVICES:
        console.print(f"[yellow]⚠️  Using custom service:[/yellow] {service}")
    
    # Get API key
    if not key:
        display_name = SERVICES.get(service, ("🔑", service, ""))[1]
        key = getpass.getpass(f"\nEnter API key for {display_name}: ")
        
        if not key:
            console.print("[red]❌ Key cannot be empty[/red]")
            raise typer.Exit(1)
        
        # Confirm
        masked = key[:4] + "*" * (len(key) - 8) + key[-4:] if len(key) > 8 else "****"
        if not Confirm.ask(f"Save key: [dim]{masked}[/dim]?", default=True):
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit()
    
    # Check for metadata
    metadata = {}
    if service in ["azure_openai"]:
        metadata['resource'] = Prompt.ask("Resource name (optional)", default="").strip() or None
    elif service in ["weaviate", "qdrant", "milvus"]:
        metadata['cluster'] = Prompt.ask("Cluster name (optional)", default="").strip() or None
    elif service == "supabase":
        metadata['project'] = Prompt.ask("Project ID (optional)", default="").strip() or None
    elif service == "cloudinary":
        metadata['cloud_name'] = Prompt.ask("Cloud name (optional)", default="").strip() or None
    elif service == "twilio":
        metadata['account_sid'] = Prompt.ask("Account SID (optional)", default="").strip() or None
    
    # Save to database
    encrypted = cipher.encrypt(key.encode()).decode()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO api_keys (service, key_value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(service) DO UPDATE SET
            key_value=excluded.key_value,
            updated_at=CURRENT_TIMESTAMP
    ''', (service, encrypted))
    
    if metadata:
        fields = list(metadata.keys())
        values = list(metadata.values())
        placeholders = ', '.join(['?'] * (len(fields) + 1))
        
        cursor.execute(f'''
            INSERT INTO service_metadata (service, {', '.join(fields)})
            VALUES ({placeholders})
            ON CONFLICT(service) DO UPDATE SET
                {', '.join([f"{f}=excluded.{f}" for f in fields])}
        ''', tuple([service] + values))
    
    conn.commit()
    conn.close()
    
    log_action("ADD", service, "key_added")
    
    icon, name, _ = SERVICES.get(service, ("🔑", service, ""))
    console.print(f"\n[bold green]✅ Added {icon} {name}[/bold green]")


@app.command()
def list_services():
    """📋 List all configured services."""
    if not DB_PATH.exists():
        console.print("[yellow]📭 No vault found.[/yellow]")
        console.print("\n[dim]Initialize with:[/dim] [cyan]./cli.py init[/cyan]")
        raise typer.Exit()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT k.service, k.created_at, k.updated_at,
               m.cluster, m.project, m.resource, m.cloud_name
        FROM api_keys k
        LEFT JOIN service_metadata m ON k.service = m.service
        ORDER BY k.service
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        console.print("[yellow]📭 No keys configured[/yellow]")
        console.print("\n[dim]Add your first key:[/dim] [cyan]./cli.py add[/cyan]")
        return
    
    console.print(f"\n[bold]📋 Configured Services ({len(rows)})[/bold]\n")
    
    table = Table(
        title="Your API Keys",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    
    table.add_column("Service", style="cyan", min_width=15)
    table.add_column("Name", min_width=20)
    table.add_column("Last Updated", min_width=20)
    table.add_column("Details", min_width=25)
    
    for row in rows:
        service, created, updated, cluster, project, resource, cloud_name = row
        icon, name, _ = SERVICES.get(service, ("🔑", service, ""))
        
        details = []
        if cluster:
            details.append(f"cluster: {cluster}")
        if project:
            details.append(f"project: {project}")
        if resource:
            details.append(f"resource: {resource}")
        if cloud_name:
            details.append(f"cloud: {cloud_name}")
        
        details_str = "\n".join(details) if details else "—"
        
        table.add_row(
            f"{icon} {service}",
            name,
            updated,
            details_str
        )
    
    console.print(table)
    console.print()


@app.command()
def remove(
    service: str = typer.Argument(..., help="Service name to remove")
):
    """🗑️ Remove a service key."""
    cipher = get_cipher()
    
    icon, name, _ = SERVICES.get(service, ("🔑", service, ""))
    
    if not Confirm.ask(f"Remove {icon} [cyan]{name}[/cyan]? This cannot be undone!", default=False):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM service_metadata WHERE service = ?', (service,))
    cursor.execute('DELETE FROM api_keys WHERE service = ?', (service,))
    
    if cursor.rowcount > 0:
        conn.commit()
        log_action("REMOVE", service, "key_removed")
        console.print(f"[bold green]✅ Removed {icon} {name}[/bold green]")
    else:
        console.print(f"[red]❌ Service not found: {service}[/red]")
    
    conn.close()


@app.command()
def audit(
    lines: int = typer.Option(50, "--lines", "-n", help="Number of entries to show")
):
    """📜 Show audit log."""
    if not AUDIT_LOG.exists():
        console.print("[yellow]📭 No audit log found[/yellow]")
        raise typer.Exit()
    
    with open(AUDIT_LOG, 'r') as f:
        all_lines = f.readlines()
    
    if not all_lines:
        console.print("[yellow]📭 Audit log is empty[/yellow]")
        return
    
    console.print(f"\n[bold]📜 Audit Log[/bold] [dim](last {min(lines, len(all_lines))} of {len(all_lines)} entries)[/dim]\n")
    
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Timestamp", style="dim", min_width=20)
    table.add_column("User", min_width=10)
    table.add_column("Action", style="cyan", min_width=10)
    table.add_column("Service", min_width=15)
    table.add_column("Details", min_width=20)
    
    for line in all_lines[-lines:]:
        line = line.strip()
        if not line:
            continue
        
        # Parse log entry
        parts = line.split('] ')
        if len(parts) >= 2:
            timestamp = parts[0].strip('[')
            rest = parts[1]
            
            user = "system"
            action = ""
            service = ""
            details = ""
            
            if '[' in rest:
                user = rest.split('[')[1].split(']')[0]
                rest = rest.split(']', 1)[1].strip()
            
            if 'service=' in rest:
                action = rest.split('service=')[0].strip()
                service_part = rest.split('service=')[1]
                if ' ' in service_part:
                    service = service_part.split()[0]
                    details = ' '.join(service_part.split()[1:])
                else:
                    service = service_part
            else:
                action = rest
            
            icon, _, _ = SERVICES.get(service, ("", service, ""))
            
            table.add_row(
                timestamp,
                user,
                action,
                f"{icon} {service}" if service else "—",
                details or "—"
            )
    
    console.print(table)
    console.print()


@app.command()
def export_env():
    """📤 Export keys to .env format."""
    cipher = get_cipher()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT service, key_value FROM api_keys')
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        console.print("[yellow]📭 No keys to export[/yellow]")
        raise typer.Exit()
    
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
    }
    
    console.print("\n[bold]📤 Environment Variables Export[/bold]\n")
    console.print("[dim]# Copy these to your .env file:[/dim]\n")
    
    for service, encrypted in rows:
        try:
            decrypted = cipher.decrypt(encrypted.encode()).decode()
            env_var = env_mappings.get(service, f"{service.upper()}_API_KEY")
            console.print(f"[green]{env_var}[/green]=[dim]{decrypted[:10]}...[/dim]")
        except Exception as e:
            console.print(f"[red]# Error decrypting {service}: {e}[/red]")
    
    log_action("EXPORT", details="keys_exported_to_env")
    console.print("\n[dim]# End of export[/dim]\n")


@app.command()
def status():
    """ℹ️ Show vault status."""
    print_banner()
    
    if not APP_DIR.exists():
        console.print("[yellow]⚠️  Vault not initialized[/yellow]")
        console.print("\n[dim]Run:[/dim] [cyan]./cli.py init[/cyan]")
        return
    
    # Count keys
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM api_keys')
    key_count = cursor.fetchone()[0]
    conn.close()
    
    # Get file sizes
    db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    audit_size = AUDIT_LOG.stat().st_size if AUDIT_LOG.exists() else 0
    
    console.print("\n[bold]Vault Status[/bold]\n")
    
    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    
    table.add_row("Location", str(APP_DIR))
    table.add_row("Keys stored", str(key_count))
    table.add_row("Database size", f"{db_size / 1024:.1f} KB")
    table.add_row("Audit log size", f"{audit_size / 1024:.1f} KB")
    table.add_row("Encryption", "Fernet (AES-128-CBC + HMAC)")
    table.add_row("Permissions", "600 (owner only)")
    
    console.print(table)
    console.print()


@app.callback()
def callback():
    """🔐 Agent Vault - Secure API Key Management"""
    pass


if __name__ == "__main__":
    app()
