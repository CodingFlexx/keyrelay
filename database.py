"""
KeyRelay Database Module

SQLite database with Fernet encryption for secure API key storage.
"""

import base64
import functools
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import bcrypt
from cryptography.fernet import Fernet


def retry_on_db_error(max_retries=3, delay=0.1):
    """Decorator to retry database operations on transient errors."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    last_exception = e
                    if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                        time.sleep(delay * (attempt + 1))
                        continue
                    raise
                except Exception:
                    raise
            raise last_exception
        return wrapper
    return decorator

# Configuration
APP_DIR = Path(
    os.getenv("AGENT_VAULT_APP_DIR", str(Path.home() / ".agent-vault"))
).expanduser()
DB_PATH = APP_DIR / "vault.db"

# Encryption key from environment variable
VAULT_KEY_ENV = "AGENT_VAULT_KEY"


def get_encryption_key() -> bytes:
    """Get encryption key from environment variable."""
    key = os.getenv(VAULT_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"Environment variable {VAULT_KEY_ENV} not set. "
            "Generate a key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    if len(key) == 44:
        return key.encode()
    else:
        import hashlib
        salt = hashlib.sha256(b"keyrelay-vault-" + key[:8].encode()).digest()
        derived = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 200000)
        return base64.urlsafe_b64encode(derived)


def get_cipher() -> Fernet:
    """Get Fernet cipher instance."""
    return Fernet(get_encryption_key())


def encrypt_value(value: str) -> str:
    """Encrypt a string value."""
    cipher = get_cipher()
    return cipher.encrypt(value.encode()).decode()


def decrypt_value(encrypted: str) -> str:
    """Decrypt an encrypted string value."""
    cipher = get_cipher()
    return cipher.decrypt(encrypted.encode()).decode()


@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def init_database():
    """Initialize the database with all required tables."""
    APP_DIR.mkdir(mode=0o700, exist_ok=True)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # API Keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT UNIQUE NOT NULL,
                encrypted_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                metadata TEXT  -- JSON string for additional service-specific data
            )
        ''')
        
        # Audit logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                service TEXT,
                endpoint TEXT,
                client_ip TEXT,
                success BOOLEAN,
                error_message TEXT,
                request_method TEXT,
                response_status INTEGER,
                user_agent TEXT
            )
        ''')
        
        # Users table for RBAC
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user' CHECK(role IN ('admin', 'user')),
                api_key_hash TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_access TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Service metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS service_metadata (
                service_name TEXT PRIMARY KEY,
                cluster TEXT,
                project TEXT,
                resource TEXT,
                cloud_name TEXT,
                account_sid TEXT,
                region TEXT,
                base_url TEXT,
                domain TEXT,
                shop TEXT,
                FOREIGN KEY (service_name) REFERENCES api_keys(service_name)
            )
        ''')

        # Backward-compatible migrations for older vaults
        cursor.execute("PRAGMA table_info(service_metadata)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        if "domain" not in existing_columns:
            cursor.execute("ALTER TABLE service_metadata ADD COLUMN domain TEXT")
        if "shop" not in existing_columns:
            cursor.execute("ALTER TABLE service_metadata ADD COLUMN shop TEXT")
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_service ON audit_logs(service)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)')
        
        conn.commit()
    
    # Set restrictive permissions
    os.chmod(DB_PATH, 0o600)


# API Key Operations

@retry_on_db_error(max_retries=3)
def add_api_key(service_name: str, api_key: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
    """Add or update an API key."""
    try:
        encrypted = encrypt_value(api_key)
        meta_json = json.dumps(metadata) if metadata else None
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO api_keys (service_name, encrypted_key, metadata, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(service_name) DO UPDATE SET
                    encrypted_key=excluded.encrypted_key,
                    metadata=excluded.metadata,
                    updated_at=CURRENT_TIMESTAMP,
                    is_active=1
            ''', (service_name, encrypted, meta_json))
            conn.commit()
        return True
    except Exception as e:
        print(f"Error adding API key: {e}")
        return False


@retry_on_db_error(max_retries=3)
def get_api_key(service_name: str) -> Optional[str]:
    """Get decrypted API key for a service."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT encrypted_key FROM api_keys 
                WHERE service_name = ? AND is_active = 1
            ''', (service_name,))
            row = cursor.fetchone()
            
            if row:
                return decrypt_value(row['encrypted_key'])
            return None
    except Exception as e:
        print(f"Error retrieving API key: {e}")
        return None


def list_api_keys() -> List[Dict[str, Any]]:
    """List all API keys (without decrypted values)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                k.service_name,
                k.created_at,
                k.updated_at,
                k.is_active,
                k.metadata,
                m.cluster,
                m.project,
                m.resource,
                m.cloud_name,
                m.account_sid,
                m.region,
                m.base_url,
                m.domain,
                m.shop
            FROM api_keys k
            LEFT JOIN service_metadata m ON k.service_name = m.service_name
            ORDER BY k.service_name
        ''')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_service_metadata(service_name: str) -> Dict[str, Any]:
    """Get merged metadata for a service from both metadata stores."""
    merged: Dict[str, Any] = {}
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                k.metadata,
                m.cluster,
                m.project,
                m.resource,
                m.cloud_name,
                m.account_sid,
                m.region,
                m.base_url,
                m.domain,
                m.shop
            FROM api_keys k
            LEFT JOIN service_metadata m ON k.service_name = m.service_name
            WHERE k.service_name = ?
            LIMIT 1
            """,
            (service_name,),
        )
        row = cursor.fetchone()
        if not row:
            return merged

        if row["metadata"]:
            try:
                parsed = json.loads(row["metadata"])
                if isinstance(parsed, dict):
                    merged.update(parsed)
            except json.JSONDecodeError:
                pass

        for field in (
            "cluster",
            "project",
            "resource",
            "cloud_name",
            "account_sid",
            "region",
            "base_url",
            "domain",
            "shop",
        ):
            value = row[field]
            if value:
                merged[field] = value
    return merged


def remove_api_key(service_name: str) -> bool:
    """Remove an API key."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM service_metadata WHERE service_name = ?', (service_name,))
            cursor.execute('DELETE FROM api_keys WHERE service_name = ?', (service_name,))
            deleted_keys = cursor.rowcount
            conn.commit()
            return deleted_keys > 0
    except Exception as e:
        print(f"Error removing API key: {e}")
        return False


def rotate_api_key(service_name: str, new_key: str) -> bool:
    """Rotate an API key (update with new value)."""
    return add_api_key(service_name, new_key)


def set_service_metadata(service_name: str, **kwargs) -> bool:
    """Set metadata for a service."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            fields = []
            values = []
            for key, value in kwargs.items():
                if value is not None:
                    fields.append(key)
                    values.append(value)
            
            if not fields:
                return True
            
            placeholders = ', '.join(['?'] * (len(fields) + 1))
            update_clause = ', '.join([f"{f}=excluded.{f}" for f in fields])
            
            cursor.execute(f'''
                INSERT INTO service_metadata (service_name, {', '.join(fields)})
                VALUES ({placeholders})
                ON CONFLICT(service_name) DO UPDATE SET
                    {update_clause}
            ''', tuple([service_name] + values))
            conn.commit()
            return True
    except Exception as e:
        print(f"Error setting metadata: {e}")
        return False


# Audit Log Operations

_MAX_AUDIT_ROWS = int(os.getenv("AGENT_VAULT_MAX_AUDIT_ROWS", "100000"))


def log_request(
    service: str,
    endpoint: str,
    client_ip: str,
    success: bool,
    request_method: str = "GET",
    response_status: Optional[int] = None,
    error_message: Optional[str] = None,
    user_agent: Optional[str] = None
):
    """Log a request to the audit log."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_logs 
                (service, endpoint, client_ip, success, request_method, 
                 response_status, error_message, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (service, endpoint, client_ip, success, request_method,
                  response_status, error_message, user_agent))
            cursor.execute('SELECT COUNT(*) FROM audit_logs')
            count = cursor.fetchone()[0]
            if count > _MAX_AUDIT_ROWS:
                cursor.execute('''
                    DELETE FROM audit_logs WHERE id IN (
                        SELECT id FROM audit_logs ORDER BY timestamp ASC
                        LIMIT ?
                    )
                ''', (count - _MAX_AUDIT_ROWS,))
            conn.commit()
    except Exception as e:
        print(f"Error logging request: {e}")


def get_audit_logs(
    service: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """Get audit logs with optional filtering."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if service:
            cursor.execute('''
                SELECT * FROM audit_logs 
                WHERE service = ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            ''', (service, limit, offset))
        else:
            cursor.execute('''
                SELECT * FROM audit_logs 
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_audit_stats() -> Dict[str, Any]:
    """Get audit statistics."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Total requests
        cursor.execute('SELECT COUNT(*) FROM audit_logs')
        total = cursor.fetchone()[0]
        
        # Successful requests
        cursor.execute('SELECT COUNT(*) FROM audit_logs WHERE success = 1')
        successful = cursor.fetchone()[0]
        
        # Failed requests
        cursor.execute('SELECT COUNT(*) FROM audit_logs WHERE success = 0')
        failed = cursor.fetchone()[0]
        
        # Requests by service
        cursor.execute('''
            SELECT service, COUNT(*) as count 
            FROM audit_logs 
            GROUP BY service 
            ORDER BY count DESC
        ''')
        by_service = {row['service']: row['count'] for row in cursor.fetchall()}
        
        return {
            'total_requests': total,
            'successful': successful,
            'failed': failed,
            'by_service': by_service
        }


# User/RBAC Operations

def hash_password(password: str) -> str:
    """Hash a password for storage."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against bcrypt hash with legacy fallback support."""
    # Legacy fallback for older PBKDF2 hashes to keep existing users working.
    if not stored_hash.startswith("$2"):
        import hashlib

        legacy_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), b"agent-vault", 100000
        ).hex()
        return legacy_hash == stored_hash

    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except ValueError:
        return False


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage."""
    import hashlib
    return hashlib.sha256(api_key.encode()).hexdigest()


def create_user(username: str, password: str, role: str = "user") -> Optional[str]:
    """Create a new user and return their API key."""
    import secrets
    api_key = secrets.token_urlsafe(32)
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, role, api_key_hash)
                VALUES (?, ?, ?, ?)
            ''', (username, hash_password(password), role, hash_api_key(api_key)))
            conn.commit()
            return api_key
    except sqlite3.IntegrityError:
        print(f"User {username} already exists")
        return None
    except Exception as e:
        print(f"Error creating user: {e}")
        return None


def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify user credentials."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, role, is_active, password_hash FROM users 
            WHERE username = ? AND is_active = 1
        ''', (username,))
        row = cursor.fetchone()

        if row and verify_password(password, row["password_hash"]):
            # Update last access
            cursor.execute(
                '''
                UPDATE users SET last_access = CURRENT_TIMESTAMP 
                WHERE username = ?
            ''',
                (username,),
            )
            conn.commit()
            user = dict(row)
            user.pop("password_hash", None)
            return user
        return None


def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Verify an API key and return user info."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, role, is_active FROM users 
            WHERE api_key_hash = ? AND is_active = 1
        ''', (hash_api_key(api_key),))
        row = cursor.fetchone()
        
        if row:
            # Update last access
            cursor.execute('''
                UPDATE users SET last_access = CURRENT_TIMESTAMP 
                WHERE api_key_hash = ?
            ''', (hash_api_key(api_key),))
            conn.commit()
            return dict(row)
        return None


def list_users() -> List[Dict[str, Any]]:
    """List all users."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, role, created_at, last_access, is_active 
            FROM users
            ORDER BY created_at
        ''')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def delete_user(username: str) -> bool:
    """Delete a user."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            conn.commit()
            return cursor.rowcount > 0
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False


if __name__ == "__main__":
    # Test the database
    print("Initializing database...")
    init_database()
    print(f"Database created at: {DB_PATH}")
    
    # Test encryption
    test_key = "test-api-key-12345"
    encrypted = encrypt_value(test_key)
    decrypted = decrypt_value(encrypted)
    print(f"Encryption test: {'✓ PASS' if decrypted == test_key else '✗ FAIL'}")
    
    # Test API key operations
    add_api_key("test_service", "sk-test123", {"region": "us-east-1"})
    retrieved = get_api_key("test_service")
    print(f"API key storage test: {'✓ PASS' if retrieved == 'sk-test123' else '✗ FAIL'}")
    
    # Test audit logging
    log_request("test_service", "/test", "127.0.0.1", True, "GET", 200)
    logs = get_audit_logs(limit=1)
    print(f"Audit logging test: {'✓ PASS' if len(logs) > 0 else '✗ FAIL'}")
    
    # Cleanup
    remove_api_key("test_service")
    print("\nAll tests passed! Database is ready.")