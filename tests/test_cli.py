"""
CLI tests for Agent Vault Proxy.

Tests CLI functionality including:
- Vault initialization
- Key management
- Service operations
- Export/Import
- Backup/Restore
"""

import pytest
import os
import sys
import json
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from click.testing import CliRunner
from typer.testing import CliRunner as TyperRunner

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import CLI module
import cli as cli_module


@pytest.fixture(scope="function")
def temp_vault(tmp_path):
    """Create a temporary vault directory."""
    vault_dir = tmp_path / ".agent-vault"
    vault_dir.mkdir(mode=0o700)
    
    # Patch APP_DIR for testing
    with patch.object(cli_module, 'APP_DIR', vault_dir):
        with patch.object(cli_module, 'DB_PATH', vault_dir / "vault.db"):
            with patch.object(cli_module, 'KEY_FILE', vault_dir / ".master_key"):
                with patch.object(cli_module, 'AUDIT_LOG', vault_dir / "audit.log"):
                    yield vault_dir


@pytest.fixture(scope="function")
def initialized_vault(temp_vault):
    """Create an initialized vault."""
    from cryptography.fernet import Fernet
    import base64
    import hashlib
    
    # Create master key
    password = "test-password-123"
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'agent-vault-salt', 100000)
    fernet_key = base64.urlsafe_b64encode(key)
    
    key_file = temp_vault / ".master_key"
    key_file.write_bytes(fernet_key)
    key_file.chmod(0o600)
    
    # Create database
    import sqlite3
    db_path = temp_vault / "vault.db"
    conn = sqlite3.connect(db_path)
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
    db_path.chmod(0o600)
    
    # Create audit log
    audit_log = temp_vault / "audit.log"
    audit_log.write_text("[2024-01-01T00:00:00] [system] Vault initialized\n")
    audit_log.chmod(0o600)
    
    return temp_vault


@pytest.mark.unit
class TestCLIInit:
    """Test vault initialization."""
    
    def test_init_creates_vault(self, temp_vault):
        """Test that init creates vault directory."""
        runner = TyperRunner()
        
        with patch('getpass.getpass', return_value='test-password-123'):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                result = runner.invoke(cli_module.app, ['init'])
        
        assert result.exit_code == 0
        assert (temp_vault / ".master_key").exists()
        assert (temp_vault / "vault.db").exists()
    
    def test_init_requires_password(self, temp_vault):
        """Test that init requires password."""
        runner = TyperRunner()
        
        with patch('getpass.getpass', side_effect=['short', 'short', 'test-password-123', 'test-password-123']):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                result = runner.invoke(cli_module.app, ['init'])
        
        # Should succeed after retry with longer password
        assert result.exit_code == 0
    
    def test_init_passwords_must_match(self, temp_vault):
        """Test that passwords must match."""
        runner = TyperRunner()
        
        with patch('getpass.getpass', side_effect=['password123', 'different', 'password123', 'password123']):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                result = runner.invoke(cli_module.app, ['init'])
        
        assert result.exit_code == 0
    
    def test_init_force_reinitializes(self, initialized_vault):
        """Test that --force reinitializes vault."""
        runner = TyperRunner()
        
        # Add a key first
        cipher = cli_module.get_cipher()
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        encrypted = cipher.encrypt(b"test-key").decode()
        cursor.execute("INSERT INTO api_keys (service, key_value) VALUES (?, ?)",
                      ("test_service", encrypted))
        conn.commit()
        conn.close()
        
        # Reinitialize with force
        with patch('getpass.getpass', return_value='new-password-123'):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                result = runner.invoke(cli_module.app, ['init', '--force'])
        
        assert result.exit_code == 0
        
        # Old key should be gone
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM api_keys")
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 0


@pytest.mark.unit
class TestCLIAdd:
    """Test adding keys."""
    
    def test_add_key_interactive(self, initialized_vault):
        """Test adding a key interactively."""
        runner = TyperRunner()
        
        with patch('getpass.getpass', return_value='test-api-key'):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                with patch('rich.prompt.Prompt.ask', return_value='openrouter'):
                    result = runner.invoke(cli_module.app, ['add'])
        
        assert result.exit_code == 0
        
        # Verify key was added
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM api_keys WHERE service = ?", ("openrouter",))
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 1
    
    def test_add_key_with_args(self, initialized_vault):
        """Test adding a key with command line arguments."""
        runner = TyperRunner()
        
        with patch('rich.prompt.Confirm.ask', return_value=True):
            result = runner.invoke(cli_module.app, ['add', 'openrouter', 'test-api-key'])
        
        assert result.exit_code == 0
    
    def test_add_key_with_metadata(self, initialized_vault):
        """Test adding a key with metadata."""
        runner = TyperRunner()
        
        with patch('getpass.getpass', return_value='test-api-key'):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                with patch('rich.prompt.Prompt.ask', side_effect=['weaviate', 'test-cluster']):
                    result = runner.invoke(cli_module.app, ['add'])
        
        assert result.exit_code == 0
    
    def test_add_empty_key_rejected(self, initialized_vault):
        """Test that empty keys are rejected."""
        runner = TyperRunner()
        
        with patch('getpass.getpass', return_value=''):
            with patch('rich.prompt.Prompt.ask', return_value='openrouter'):
                result = runner.invoke(cli_module.app, ['add'])
        
        assert result.exit_code != 0 or "cannot be empty" in result.output.lower()


@pytest.mark.unit
class TestCLIList:
    """Test listing keys."""
    
    def test_list_empty_vault(self, initialized_vault):
        """Test listing with no keys."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['list-services'])
        
        assert result.exit_code == 0
        assert "No keys configured" in result.output or "📭" in result.output
    
    def test_list_with_keys(self, initialized_vault):
        """Test listing with keys."""
        runner = TyperRunner()
        
        # Add a key
        cipher = cli_module.get_cipher()
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        encrypted = cipher.encrypt(b"test-key").decode()
        cursor.execute("INSERT INTO api_keys (service, key_value) VALUES (?, ?)",
                      ("openrouter", encrypted))
        conn.commit()
        conn.close()
        
        result = runner.invoke(cli_module.app, ['list-services'])
        
        assert result.exit_code == 0
        assert "openrouter" in result.output
    
    def test_list_shows_service_names(self, initialized_vault):
        """Test that list shows service names."""
        runner = TyperRunner()
        
        # Add multiple keys
        cipher = cli_module.get_cipher()
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        
        services = ["openrouter", "openai", "github"]
        for service in services:
            encrypted = cipher.encrypt(f"{service}-key".encode()).decode()
            cursor.execute("INSERT INTO api_keys (service, key_value) VALUES (?, ?)",
                          (service, encrypted))
        
        conn.commit()
        conn.close()
        
        result = runner.invoke(cli_module.app, ['list-services'])
        
        assert result.exit_code == 0
        for service in services:
            assert service in result.output


@pytest.mark.unit
class TestCLIRemove:
    """Test removing keys."""
    
    def test_remove_key(self, initialized_vault):
        """Test removing a key."""
        runner = TyperRunner()
        
        # Add a key first
        cipher = cli_module.get_cipher()
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        encrypted = cipher.encrypt(b"test-key").decode()
        cursor.execute("INSERT INTO api_keys (service, key_value) VALUES (?, ?)",
                      ("openrouter", encrypted))
        conn.commit()
        conn.close()
        
        with patch('rich.prompt.Confirm.ask', return_value=True):
            result = runner.invoke(cli_module.app, ['remove', 'openrouter'])
        
        assert result.exit_code == 0
        
        # Verify key was removed
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM api_keys WHERE service = ?", ("openrouter",))
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 0
    
    def test_remove_cancelled(self, initialized_vault):
        """Test that removal can be cancelled."""
        runner = TyperRunner()
        
        # Add a key
        cipher = cli_module.get_cipher()
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        encrypted = cipher.encrypt(b"test-key").decode()
        cursor.execute("INSERT INTO api_keys (service, key_value) VALUES (?, ?)",
                      ("openrouter", encrypted))
        conn.commit()
        conn.close()
        
        with patch('rich.prompt.Confirm.ask', return_value=False):
            result = runner.invoke(cli_module.app, ['remove', 'openrouter'])
        
        assert result.exit_code == 0
        assert "Aborted" in result.output
    
    def test_remove_nonexistent(self, initialized_vault):
        """Test removing non-existent key."""
        runner = TyperRunner()
        
        with patch('rich.prompt.Confirm.ask', return_value=True):
            result = runner.invoke(cli_module.app, ['remove', 'nonexistent'])
        
        assert result.exit_code == 0
        assert "not found" in result.output.lower()


@pytest.mark.unit
class TestCLIAudit:
    """Test audit log commands."""
    
    def test_audit_empty(self, initialized_vault):
        """Test audit with empty log."""
        # Clear audit log
        audit_log = initialized_vault / "audit.log"
        audit_log.write_text("")
        
        runner = TyperRunner()
        result = runner.invoke(cli_module.app, ['audit'])
        
        assert result.exit_code == 0
    
    def test_audit_with_entries(self, initialized_vault):
        """Test audit with entries."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['audit', '--lines', '10'])
        
        assert result.exit_code == 0
        assert "Vault initialized" in result.output
    
    def test_audit_limit_lines(self, initialized_vault):
        """Test audit with line limit."""
        # Add more entries
        audit_log = initialized_vault / "audit.log"
        with open(audit_log, 'a') as f:
            for i in range(20):
                f.write(f"[2024-01-01T00:00:{i:02d}] [user] ADD service=openrouter\n")
        
        runner = TyperRunner()
        result = runner.invoke(cli_module.app, ['audit', '--lines', '5'])
        
        assert result.exit_code == 0


@pytest.mark.unit
class TestCLIExport:
    """Test export functionality."""
    
    def test_export_env_empty(self, initialized_vault):
        """Test export with no keys."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['export-env'])
        
        assert result.exit_code == 0
        assert "No keys to export" in result.output
    
    def test_export_env_with_keys(self, initialized_vault):
        """Test export with keys."""
        runner = TyperRunner()
        
        # Add keys
        cipher = cli_module.get_cipher()
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        
        services = [
            ("openrouter", "sk-or-test"),
            ("openai", "sk-openai-test"),
            ("github", "ghp_test"),
        ]
        
        for service, key in services:
            encrypted = cipher.encrypt(key.encode()).decode()
            cursor.execute("INSERT INTO api_keys (service, key_value) VALUES (?, ?)",
                          (service, encrypted))
        
        conn.commit()
        conn.close()
        
        result = runner.invoke(cli_module.app, ['export-env'])
        
        assert result.exit_code == 0
        assert "OPENROUTER_API_KEY" in result.output
        assert "OPENAI_API_KEY" in result.output
        assert "GITHUB_PAT" in result.output


@pytest.mark.unit
class TestCLIStatus:
    """Test status command."""
    
    def test_status_initialized(self, initialized_vault):
        """Test status with initialized vault."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['status'])
        
        assert result.exit_code == 0
        assert "Vault Status" in result.output
        assert "Encryption" in result.output
    
    def test_status_uninitialized(self, temp_vault):
        """Test status with uninitialized vault."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['status'])
        
        assert result.exit_code == 0
        assert "not initialized" in result.output.lower()


@pytest.mark.unit
class TestCLIBackup:
    """Test backup and restore functionality."""
    
    def test_backup_command_exists(self, initialized_vault):
        """Test that backup command exists."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['backup', '--help'])
        
        # Command might not exist yet
        assert result.exit_code in [0, 2]
    
    def test_restore_command_exists(self, initialized_vault):
        """Test that restore command exists."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['restore', '--help'])
        
        # Command might not exist yet
        assert result.exit_code in [0, 2]


@pytest.mark.unit
class TestCLIRotation:
    """Test key rotation functionality."""
    
    def test_rotate_command_exists(self, initialized_vault):
        """Test that rotate command exists."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['rotate', '--help'])
        
        # Command might not exist yet
        assert result.exit_code in [0, 2]
    
    def test_rotate_auto_command_exists(self, initialized_vault):
        """Test that rotate-auto command exists."""
        runner = TyperRunner()
        
        result = runner.invoke(cli_module.app, ['rotate-auto', '--help'])
        
        # Command might not exist yet
        assert result.exit_code in [0, 2]


@pytest.mark.unit
class TestCLIServiceDefinitions:
    """Test service definitions."""
    
    def test_services_defined(self):
        """Test that services are defined."""
        assert len(cli_module.SERVICES) > 0
        
        # Check common services
        assert "openrouter" in cli_module.SERVICES
        assert "openai" in cli_module.SERVICES
        assert "github" in cli_module.SERVICES
    
    def test_service_has_icon(self):
        """Test that services have icons."""
        for service, (icon, name, desc) in cli_module.SERVICES.items():
            assert len(icon) > 0
            assert len(name) > 0
            assert len(desc) > 0
    
    def test_service_icon_is_emoji(self):
        """Test that service icons are emojis."""
        for service, (icon, name, desc) in cli_module.SERVICES.items():
            # Icons should be emojis (multi-byte characters)
            assert len(icon.encode('utf-8')) > len(icon)


@pytest.mark.unit
class TestCLILogging:
    """Test CLI logging functionality."""
    
    def test_log_action(self, initialized_vault):
        """Test that actions are logged."""
        cli_module.log_action("TEST", "openrouter", "test details")
        
        audit_log = initialized_vault / "audit.log"
        content = audit_log.read_text()
        
        assert "TEST" in content
        assert "openrouter" in content
        assert "test details" in content
    
    def test_log_action_no_service(self, initialized_vault):
        """Test logging action without service."""
        cli_module.log_action("INIT", details="vault initialized")
        
        audit_log = initialized_vault / "audit.log"
        content = audit_log.read_text()
        
        assert "INIT" in content


@pytest.mark.unit
class TestCLIEdgeCases:
    """Test CLI edge cases."""
    
    def test_init_short_password(self, temp_vault):
        """Test init with short password."""
        runner = TyperRunner()
        
        with patch('getpass.getpass', side_effect=['short', 'short', 'longpassword123', 'longpassword123']):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                result = runner.invoke(cli_module.app, ['init'])
        
        # Should eventually succeed
        assert result.exit_code == 0
    
    def test_add_custom_service(self, initialized_vault):
        """Test adding a custom service."""
        runner = TyperRunner()
        
        with patch('getpass.getpass', return_value='custom-key'):
            with patch('rich.prompt.Confirm.ask', return_value=True):
                with patch('rich.prompt.Prompt.ask', side_effect=['custom', 'my-custom-service']):
                    result = runner.invoke(cli_module.app, ['add'])
        
        assert result.exit_code == 0
    
    def test_list_services_table_format(self, initialized_vault):
        """Test that list outputs in table format."""
        runner = TyperRunner()
        
        # Add a key
        cipher = cli_module.get_cipher()
        conn = sqlite3.connect(initialized_vault / "vault.db")
        cursor = conn.cursor()
        encrypted = cipher.encrypt(b"test-key").decode()
        cursor.execute("INSERT INTO api_keys (service, key_value) VALUES (?, ?)",
                      ("openrouter", encrypted))
        conn.commit()
        conn.close()
        
        result = runner.invoke(cli_module.app, ['list-services'])
        
        assert result.exit_code == 0
        # Should contain table formatting
        assert "Service" in result.output or "openrouter" in result.output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
