#!/usr/bin/env python3
"""
Agent Vault CLI v2 - Enhanced Key Management

A comprehensive CLI tool for managing API keys with audit logging and RBAC.
Uses Click for command-line interface.
"""

import os
import sys
import json
import getpass
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich import box

# Import database module
from database import (
    init_database, add_api_key, get_api_key, list_api_keys,
    remove_api_key, rotate_api_key, set_service_metadata,
    log_request, get_audit_logs, get_audit_stats,
    create_user, verify_user, verify_api_key, list_users, delete_user,
    DB_PATH, APP_DIR
)

console = Console()

# Extended service definitions with 40+ services
SERVICES = {
    # LLM APIs
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
    "ai21": ("🧩", "AI21 Labs", "Jurassic language models"),
    "aleph_alpha": ("🔤", "Aleph Alpha", "European LLM provider"),
    
    # Vector Databases
    "pinecone": ("🌲", "Pinecone", "Vector database"),
    "weaviate": ("🔮", "Weaviate", "AI-native vector DB"),
    "qdrant": ("🎯", "Qdrant", "Vector similarity search"),
    "chroma": ("🎨", "Chroma", "Embedding database"),
    "milvus": ("🦅", "Milvus", "Distributed vector DB"),
    "pgvector": ("🐘", "pgvector", "Postgres vector extension"),
    "redis_vector": ("🔴", "Redis Vector", "Redis vector search"),
    "faiss": ("📚", "FAISS", "Facebook AI Similarity Search"),
    
    # Search APIs
    "brave": ("🦁", "Brave Search", "Privacy-focused search"),
    "serpapi": ("🔎", "SerpAPI", "Google search API"),
    "tavily": ("📊", "Tavily", "AI search engine"),
    "exa": ("🔬", "Exa", "Neural search"),
    "perplexity": ("❓", "Perplexity", "AI answer engine"),
    "bing": ("🔷", "Bing Search", "Microsoft search API"),
    "google_custom_search": ("🔍", "Google Custom Search", "Programmable search"),
    
    # Git & Dev
    "github": ("🐙", "GitHub", "Code repository"),
    "gitlab": ("🦊", "GitLab", "DevOps platform"),
    "bitbucket": ("🪣", "Bitbucket", "Git repository hosting"),
    "azure_devops": ("🔷", "Azure DevOps", "Microsoft DevOps"),
    
    # Cloud & Storage
    "aws": ("☁️", "AWS", "Amazon Web Services"),
    "gcp": ("🔵", "Google Cloud", "Google Cloud Platform"),
    "azure": ("🔷", "Azure", "Microsoft Azure"),
    "supabase": ("⚡", "Supabase", "Firebase alternative"),
    "firebase": ("🔥", "Firebase", "Google app platform"),
    "mongodb": ("🍃", "MongoDB", "NoSQL database"),
    "planetscale": ("🪐", "PlanetScale", "MySQL platform"),
    "neon": ("💡", "Neon", "Serverless Postgres"),
    "upstash": ("⚡", "Upstash", "Serverless Redis/Kafka"),
    
    # Communication
    "slack": ("💬", "Slack", "Team messaging"),
    "discord": ("🎮", "Discord", "Community chat"),
    "telegram": ("✈️", "Telegram", "Secure messaging"),
    "twilio": ("📞", "Twilio", "Communication APIs"),
    "sendgrid": ("📧", "SendGrid", "Email delivery"),
    "mailgun": ("🔫", "Mailgun", "Email service"),
    "postmark": ("📮", "Postmark", "Transactional email"),
    "resend": ("📤", "Resend", "Email for developers"),
    
    # Monitoring & Analytics
    "langsmith": ("🔧", "LangSmith", "LLM observability"),
    "langfuse": ("📈", "Langfuse", "LLM analytics"),
    "weights_biases": ("🏋️", "Weights & Biases", "ML experiment tracking"),
    "arize": ("📊", "Arize", "ML observability"),
    "phoenix": ("🔥", "Phoenix", "LLM observability"),
    "promptlayer": ("📋", "PromptLayer", "Prompt management"),
    "helicone": ("🚁", "Helicone", "LLM monitoring"),
    
    # Image & Media
    "replicate": ("🔄", "Replicate", "ML model hosting"),
    "stability": ("🎭", "Stability AI", "Image generation"),
    "cloudinary": ("☁️", "Cloudinary", "Media management"),
    "imgix": ("🖼️", "Imgix", "Image processing"),
    "unsplash": ("📷", "Unsplash", "Stock photos"),
    
    # Other AI Services
    "huggingface": ("🤗", "Hugging Face", "ML community"),
    "assemblyai": ("🎤", "AssemblyAI", "Speech recognition"),
    "elevenlabs": ("🗣️", "ElevenLabs", "Voice synthesis"),
    "openvoice": ("🎙️", "OpenVoice", "Voice cloning"),
    "whisper": ("👂", "Whisper API", "Speech-to-text"),
    "deepgram": ("🎧", "Deepgram", "Voice AI"),
    "rev_ai": ("📝", "Rev.ai", "Speech-to-text"),
    
    # Productivity & Collaboration
    "notion": ("📓", "Notion", "Workspace & docs"),
    "airtable": ("🗂️", "Airtable", "Database spreadsheet"),
    "trello": ("📋", "Trello", "Project management"),
    "asana": ("✅", "Asana", "Task management"),
    "linear": ("📐", "Linear", "Issue tracking"),
    "jira": ("🐛", "Jira", "Project management"),
    "confluence": ("📄", "Confluence", "Documentation"),
    
    # Payment & Commerce
    "stripe": ("💳", "Stripe", "Payment processing"),
    "paypal": ("💰", "PayPal", "Payment platform"),
    "shopify": ("🛒", "Shopify", "E-commerce platform"),
    
    # Security & Auth
    "auth0": ("🔐", "Auth0", "Authentication"),
    "okta": ("🆗", "Okta", "Identity management"),
    "1password": ("🔑", "1Password", "Password manager"),
}


def print_banner():
    """Print welcome banner."""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🔐  [bold cyan]AGENT VAULT PROXY v2.0[/bold cyan] - Phase 2 Complete      ║
║                                                          ║
║   Secure API Key Management with Encryption + Audit      ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""
    console.print(Panel(banner, border_style="cyan", box=box.DOUBLE))


@click.group()
@click.version_option(version="2.0.0", prog_name="agent-vault")
@click.pass_context
def cli(ctx):
    """🔐 Agent Vault Proxy - Secure API Key Management CLI"""
    ctx.ensure_object(dict)
    
    # Check if database exists, if not suggest init
    if not DB_PATH.exists() and ctx.invoked_subcommand != "init":
        console.print("[yellow]⚠️  Vault not initialized![/yellow]")
        console.print("\n[dim]Run:[/dim] [cyan]python cli_v2.py init[/cyan]")
        raise click.Abort()


@cli.command()
def init():
    """🔐 Initialize the vault database"""
    print_banner()
    
    if DB_PATH.exists():
        if not Confirm.ask("Vault already exists. Reinitialize?", default=False):
            console.print("[dim]Aborted.[/dim]")
            return
    
    with console.status("[bold green]Initializing vault..."):
        init_database()
    
    console.print(f"\n[bold green]✅ Vault initialized successfully![/bold green]")
    console.print(f"[dim]Location:[/dim] {APP_DIR}")
    console.print(f"[dim]Database:[/dim] {DB_PATH}")
    
    console.print("\n[bold]Next steps:[/bold]")
    console.print("  [cyan]python cli_v2.py add-key[/cyan]     # Add your first API key")
    console.print("  [cyan]python cli_v2.py list-keys[/cyan]    # View all services")
    console.print("  [cyan]python cli_v2.py user-create[/cyan]  # Create admin user")


@cli.command(name="add-key")
@click.option("--service", "-s", help="Service name (e.g., openrouter)")
@click.option("--key", "-k", help="API key value")
@click.option("--interactive", "-i", is_flag=True, help="Interactive mode")
def add_key(service, key, interactive):
    """➕ Add or update an API key"""
    
    if interactive or (not service and not key):
        # Interactive mode
        console.print("\n[bold]Available services:[/bold]\n")
        
        # Show services in a grid
        table = Table(show_header=False, box=None, padding=(0, 2))
        services_list = list(SERVICES.items())
        
        for i in range(0, len(services_list), 3):
            row = []
            for j in range(3):
                if i + j < len(services_list):
                    key_name, (icon, name, desc) = services_list[i + j]
                    row.append(f"{icon} [cyan]{key_name}[/cyan]")
            if row:
                table.add_row(*row)
        
        console.print(table)
        console.print("\n[dim]Or type a custom service name[/dim]\n")
        
        service = Prompt.ask(
            "Service",
            choices=list(SERVICES.keys()) + ["custom"]
        )
        if service == "custom":
            service = Prompt.ask("Custom service name").lower().replace(" ", "_")
    
    if not service:
        service = click.prompt("Service name")
    
    if service not in SERVICES:
        console.print(f"[yellow]⚠️  Using custom service:[/yellow] {service}")
    
    # Get API key
    if not key:
        display_name = SERVICES.get(service, ("🔑", service, ""))[1]
        key = getpass.getpass(f"Enter API key for {display_name}: ")
        
        if not key:
            console.print("[red]❌ Key cannot be empty[/red]")
            return
    
    # Collect metadata based on service
    metadata = {}
    if service in ["azure_openai"]:
        metadata['resource'] = click.prompt("Resource name (optional)", default="", show_default=False) or None
    elif service in ["weaviate", "qdrant", "milvus"]:
        metadata['cluster'] = click.prompt("Cluster name (optional)", default="", show_default=False) or None
    elif service == "supabase":
        metadata['project'] = click.prompt("Project ID (optional)", default="", show_default=False) or None
    elif service == "cloudinary":
        metadata['cloud_name'] = click.prompt("Cloud name (optional)", default="", show_default=False) or None
    elif service == "twilio":
        metadata['account_sid'] = click.prompt("Account SID (optional)", default="", show_default=False) or None
    elif service in ["aws", "aws_bedrock"]:
        metadata['region'] = click.prompt("AWS Region (optional)", default="us-east-1")
    
    # Filter out None values
    metadata = {k: v for k, v in metadata.items() if v is not None}
    
    # Save to database
    with console.status("[bold green]Saving API key..."):
        success = add_api_key(service, key, metadata if metadata else None)
    
    if success:
        # Save metadata to separate table if exists
        if metadata:
            set_service_metadata(service, **metadata)
        
        icon, name, _ = SERVICES.get(service, ("🔑", service, ""))
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


@cli.command(name="list-keys")
@click.option("--show-inactive", is_flag=True, help="Show inactive keys")
def list_keys(show_inactive):
    """📋 List all configured API keys"""
    
    keys = list_api_keys()
    
    if not keys:
        console.print("[yellow]📭 No keys configured[/yellow]")
        console.print("\n[dim]Add your first key:[/dim] [cyan]python cli_v2.py add-key[/cyan]")
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
        icon, name, _ = SERVICES.get(service, ("🔑", service, ""))
        
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


@cli.command(name="remove-key")
@click.argument("service")
@click.confirmation_option(prompt="Are you sure you want to remove this key?")
def remove_key(service):
    """🗑️ Remove an API key"""
    
    icon, name, _ = SERVICES.get(service, ("🔑", service, ""))
    
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


@cli.command(name="rotate-key")
@click.argument("service")
@click.option("--new-key", "-k", help="New API key value")
def rotate_key(service, new_key):
    """🔄 Rotate (update) an API key"""
    
    icon, name, _ = SERVICES.get(service, ("🔑", service, ""))
    
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


@cli.command(name="audit-logs")
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

@cli.command(name="user-create")
@click.argument("username")
@click.option("--role", default="user", type=click.Choice(["admin", "user"]), help="User role")
@click.password_option(help="User password")
def user_create(username, role, password):
    """👤 Create a new user"""
    
    with console.status("[bold green]Creating user..."):
        api_key = create_user(username, password, role)
    
    if api_key:
        console.print(f"\n[bold green]✅ User created successfully![/bold green]")
        console.print(f"[cyan]Username:[/cyan] {username}")
        console.print(f"[cyan]Role:[/cyan] {role}")
        console.print(f"\n[bold yellow]🔑 API Key (save this!):[/bold yellow]")
        console.print(Panel(api_key, border_style="yellow"))
        console.print("[dim]This key is required to access the proxy.[/dim]")
    else:
        console.print(f"[red]❌ Failed to create user (may already exist)[/red]")


@cli.command(name="user-list")
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


@cli.command(name="user-delete")
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


@cli.command(name="user-verify")
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

@cli.command(name="export-env")
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


@cli.command(name="status")
def status():
    """ℹ️ Show vault status"""
    
    print_banner()
    
    if not APP_DIR.exists():
        console.print("[yellow]⚠️  Vault not initialized[/yellow]")
        console.print("\n[dim]Run:[/dim] [cyan]python cli_v2.py init[/cyan]")
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
    table.add_row("Environment Key", os.getenv("AGENT_VAULT_KEY", "[red]Not set[/red]")[:20] + "...")
    
    console.print(table)
    
    if keys:
        console.print("\n[bold]Configured Services:[/bold]")
        services_str = ", ".join([k['service_name'] for k in keys[:10]])
        if len(keys) > 10:
            services_str += f" and {len(keys) - 10} more"
        console.print(f"[dim]{services_str}[/dim]")
    
    console.print()


@cli.command(name="get-key")
@click.argument("service")
def get_key(service):
    """🔑 Retrieve a specific API key (decrypted)"""
    
    key = get_api_key(service)
    
    if key:
        icon, name, _ = SERVICES.get(service, ("🔑", service, ""))
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


if __name__ == "__main__":
    cli()