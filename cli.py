#!/usr/bin/env python3
"""
Agent Vault CLI - Manage API keys and configuration

Usage:
    ./cli.py init                    # Initialize vault
    ./cli.py add <service> <key>     # Add API key
    ./cli.py list                    # List configured services
    ./cli.py remove <service>        # Remove a service
    ./cli.py rotate                  # Rotate master key
    ./cli.py audit                   # Show audit log
    ./cli.py export                  # Export to env file
    ./cli.py import <file>           # Import from env file
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet

APP_DIR = Path.home() / ".agent-vault"
DB_PATH = APP_DIR / "vault.db"
KEY_FILE = APP_DIR / ".master_key"
AUDIT_LOG = APP_DIR / "audit.log"

# Service name mappings
SERVICE_NAMES = {
    "openrouter": "OpenRouter",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "gemini": "Google Gemini",
    "groq": "Groq",
    "cohere": "Cohere",
    "mistral": "Mistral AI",
    "deepseek": "DeepSeek",
    "azure_openai": "Azure OpenAI",
    "aws_bedrock": "AWS Bedrock",
    "pinecone": "Pinecone",
    "weaviate": "Weaviate",
    "qdrant": "Qdrant",
    "chroma": "Chroma",
    "milvus": "Milvus",
    "brave": "Brave Search",
    "serpapi": "SerpAPI",
    "tavily": "Tavily",
    "exa": "Exa",
    "perplexity": "Perplexity",
    "github": "GitHub",
    "gitlab": "GitLab",
    "bitbucket": "Bitbucket",
    "supabase": "Supabase",
    "firebase": "Firebase",
    "slack": "Slack",
    "discord": "Discord",
    "telegram": "Telegram",
    "twilio": "Twilio",
    "sendgrid": "SendGrid",
    "langsmith": "LangSmith",
    "langfuse": "Langfuse",
    "weights_biases": "Weights & Biases",
    "arize": "Arize",
    "replicate": "Replicate",
    "stability": "Stability AI",
    "cloudinary": "Cloudinary",
    "huggingface": "Hugging Face",
    "assemblyai": "AssemblyAI",
    "elevenlabs": "ElevenLabs",
}


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


def init_vault():
    """Initialize the vault with master password."""
    print("🔐 Agent Vault Initialization")
    print("=" * 50)
    
    if APP_DIR.exists():
        print(f"⚠️  Vault directory already exists: {APP_DIR}")
        response = input("Reinitialize? This will DELETE all existing keys! [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            return
    
    # Create directory
    APP_DIR.mkdir(mode=0o700, exist_ok=True)
    
    # Get master password
    print("\nSet a master password for the vault.")
    print("This password will be required to access your API keys.")
    
    while True:
        password = getpass.getpass("Master password: ")
        if len(password) < 8:
            print("❌ Password must be at least 8 characters")
            continue
        
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("❌ Passwords don't match")
            continue
        
        break
    
    # Generate encryption key from password
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'agent-vault-salt', 100000)
    fernet_key = base64.urlsafe_b64encode(key)
    
    # Save key file (restricted permissions)
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
    
    print("\n✅ Vault initialized successfully!")
    print(f"📁 Location: {APP_DIR}")
    print(f"🔑 Key file: {KEY_FILE}")
    print(f"🗄️  Database: {DB_PATH}")
    print("\nNext steps:")
    print("  ./cli.py add openrouter <your-key>")
    print("  ./cli.py list")


def get_cipher() -> Fernet:
    """Get cipher instance."""
    if not KEY_FILE.exists():
        print("❌ Vault not initialized. Run: ./cli.py init")
        sys.exit(1)
    
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
    
    return Fernet(key)


def add_key(service: str, key_value: str, **metadata):
    """Add or update an API key."""
    cipher = get_cipher()
    encrypted = cipher.encrypt(key_value.encode()).decode()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Insert or update key
    cursor.execute('''
        INSERT INTO api_keys (service, key_value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(service) DO UPDATE SET
            key_value=excluded.key_value,
            updated_at=CURRENT_TIMESTAMP
    ''', (service, encrypted))
    
    # Update metadata if provided
    if metadata:
        fields = []
        values = []
        for field, value in metadata.items():
            if value:
                fields.append(f"{field} = ?")
                values.append(value)
        
        if fields:
            values.append(service)
            cursor.execute(f'''
                INSERT INTO service_metadata (service, {', '.join(metadata.keys())})
                VALUES ({', '.join(['?'] * (len(metadata) + 1))})
                ON CONFLICT(service) DO UPDATE SET
                    {', '.join([f"{k}=excluded.{k}" for k in metadata.keys()])}
            ''', tuple([service] + list(metadata.values())))
    
    conn.commit()
    conn.close()
    
    log_action("ADD", service, "key_added")
    
    display_name = SERVICE_NAMES.get(service, service)
    print(f"✅ Added/updated key for {display_name} ({service})")


def list_keys():
    """List all configured services."""
    if not DB_PATH.exists():
        print("❌ Vault not initialized. Run: ./cli.py init")
        return
    
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
        print("📭 No keys configured")
        print("\nAdd a key with:")
        print("  ./cli.py add <service> <key>")
        return
    
    print("\n📋 Configured Services:")
    print("=" * 80)
    print(f"{'Service':<20} {'Name':<25} {'Updated':<20} {'Extras'}")
    print("-" * 80)
    
    for row in rows:
        service, created, updated, cluster, project, resource, cloud_name = row
        display_name = SERVICE_NAMES.get(service, service)[:24]
        
        extras = []
        if cluster:
            extras.append(f"cluster={cluster}")
        if project:
            extras.append(f"project={project}")
        if resource:
            extras.append(f"resource={resource}")
        if cloud_name:
            extras.append(f"cloud={cloud_name}")
        
        extras_str = ", ".join(extras) if extras else "-"
        
        print(f"{service:<20} {display_name:<25} {updated:<20} {extras_str}")
    
    print("=" * 80)
    print(f"Total: {len(rows)} service(s)")


def remove_key(service: str):
    """Remove a service key."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM service_metadata WHERE service = ?', (service,))
    cursor.execute('DELETE FROM api_keys WHERE service = ?', (service,))
    
    if cursor.rowcount > 0:
        conn.commit()
        log_action("REMOVE", service, "key_removed")
        display_name = SERVICE_NAMES.get(service, service)
        print(f"✅ Removed key for {display_name} ({service})")
    else:
        print(f"❌ Service not found: {service}")
    
    conn.close()


def show_audit():
    """Show audit log."""
    if not AUDIT_LOG.exists():
        print("📭 No audit log found")
        return
    
    print("\n📜 Audit Log:")
    print("=" * 80)
    
    with open(AUDIT_LOG, 'r') as f:
        lines = f.readlines()
    
    # Show last 50 entries
    for line in lines[-50:]:
        print(line.rstrip())
    
    print("=" * 80)
    print(f"Showing last {min(50, len(lines))} of {len(lines)} entries")


def export_env():
    """Export keys to .env format."""
    cipher = get_cipher()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT service, key_value FROM api_keys')
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        print("❌ No keys to export")
        return
    
    print("\n# Agent Vault Export")
    print("# Generated:", datetime.now().isoformat())
    print()
    
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
    
    for service, encrypted in rows:
        try:
            decrypted = cipher.decrypt(encrypted.encode()).decode()
            env_var = env_mappings.get(service, f"{service.upper()}_API_KEY")
            print(f"{env_var}={decrypted}")
        except Exception as e:
            print(f"# Error decrypting {service}: {e}")
    
    log_action("EXPORT", details="keys_exported_to_env")
    print("\n# End of export")


def interactive_add():
    """Interactive key addition."""
    print("\n🔑 Add API Key")
    print("=" * 50)
    
    print("\nAvailable services:")
    services = sorted(SERVICE_NAMES.items(), key=lambda x: x[1])
    for i, (key, name) in enumerate(services, 1):
        print(f"  {i:2}. {name:<25} ({key})")
    
    print("\nOr type a custom service name")
    
    choice = input("\nSelect service (number or name): ").strip()
    
    # Check if number
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(services):
            service = services[idx][0]
        else:
            print("❌ Invalid selection")
            return
    except ValueError:
        service = choice.lower().replace(" ", "_")
    
    if service not in SERVICE_NAMES:
        print(f"⚠️  Using custom service: {service}")
    
    # Get key
    key_value = getpass.getpass(f"Enter API key for {SERVICE_NAMES.get(service, service)}: ")
    
    if not key_value:
        print("❌ Key cannot be empty")
        return
    
    # Check for metadata
    metadata = {}
    
    if service in ["azure_openai"]:
        metadata['resource'] = input("Resource name (optional): ").strip() or None
    elif service in ["weaviate", "qdrant", "milvus"]:
        metadata['cluster'] = input("Cluster name (optional): ").strip() or None
    elif service == "supabase":
        metadata['project'] = input("Project ID (optional): ").strip() or None
    elif service == "cloudinary":
        metadata['cloud_name'] = input("Cloud name (optional): ").strip() or None
    elif service == "twilio":
        metadata['account_sid'] = input("Account SID (optional): ").strip() or None
    
    add_key(service, key_value, **metadata)


def main():
    parser = argparse.ArgumentParser(
        description="Agent Vault CLI - Manage API keys securely",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./cli.py init                           # Initialize vault
  ./cli.py add openrouter sk-or-v1-...    # Add OpenRouter key
  ./cli.py add                            # Interactive mode
  ./cli.py list                           # Show all services
  ./cli.py remove openrouter              # Remove a service
  ./cli.py audit                          # View audit log
  ./cli.py export > .env                  # Export to env file
        """
    )
    
    parser.add_argument("command", choices=[
        "init", "add", "list", "remove", "audit", "export", "import"
    ], help="Command to run")
    parser.add_argument("service", nargs="?", help="Service name")
    parser.add_argument("key", nargs="?", help="API key value")
    
    args = parser.parse_args()
    
    if args.command == "init":
        init_vault()
    elif args.command == "add":
        if args.service and args.key:
            add_key(args.service, args.key)
        else:
            interactive_add()
    elif args.command == "list":
        list_keys()
    elif args.command == "remove":
        if not args.service:
            print("❌ Service name required")
            sys.exit(1)
        remove_key(args.service)
    elif args.command == "audit":
        show_audit()
    elif args.command == "export":
        export_env()
    elif args.command == "import":
        print("❌ Import not yet implemented")
        sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
