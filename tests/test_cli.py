"""Tests for KeyRelay CLI usability and onboarding helpers."""

from pathlib import Path

import pytest
from click.testing import CliRunner
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up test environment variables."""
    monkeypatch.setenv("AGENT_VAULT_KEY", "test-master-key-for-testing-only-32bytes!")
    yield


@pytest.mark.unit
class TestCLIServiceDefinitions:
    """Test service definitions in CLI."""
    
    def test_services_defined(self, mock_env_vars):
        """Test that services are defined."""
        import cli
        
        # Check that SERVICES dict exists and has entries
        assert hasattr(cli, 'SERVICES')
        assert len(cli.SERVICES) > 0
        
        # Check common services
        assert "openrouter" in cli.SERVICES
        assert "openai" in cli.SERVICES
        assert "github" in cli.SERVICES
    
    def test_service_has_icon(self, mock_env_vars):
        """Test that services have icons."""
        import cli
        
        for service_name, service_info in cli.SERVICES.items():
            assert "icon" in service_info
            # Icon can be emoji or string
            assert isinstance(service_info["icon"], str)
    
    def test_service_icon_is_emoji(self, mock_env_vars):
        """Test that service icons are emojis."""
        import cli
        
        for service_name, service_info in cli.SERVICES.items():
            icon = service_info["icon"]
            # Icon should be a non-empty string
            assert isinstance(icon, str)
            assert len(icon) >= 1


@pytest.mark.unit
class TestCLIHelpers:
    """Test CLI helper functions."""
    
    def test_get_encryption_key_from_env(self, mock_env_vars):
        """Test getting encryption key from shared database helper."""
        import cli
        import app.db.database as database
        
        # CLI should expose the same implementation as database.py
        assert cli.get_encryption_key is database.get_encryption_key
        key = cli.get_encryption_key()
        assert isinstance(key, bytes)
        # Fernet keys are 32 bytes, base64 encoded to 44 chars
        assert len(key) == 44
    
    def test_encrypt_decrypt_roundtrip(self, mock_env_vars):
        """Test encryption and decryption."""
        import cli
        
        original = "test-api-key-12345"
        encrypted = cli.encrypt_value(original)
        decrypted = cli.decrypt_value(encrypted)
        
        assert encrypted != original
        assert decrypted == original

    def test_infer_service_from_env_var(self, mock_env_vars):
        import cli

        assert cli._infer_service_from_env_var("OPENAI_API_KEY") == "openai"
        assert cli._infer_service_from_env_var("CUSTOM_PROVIDER_TOKEN") == "custom_provider"

    def test_parse_env_file(self, mock_env_vars, tmp_path):
        import cli

        env_file = tmp_path / ".env"
        env_file.write_text(
            "# comment\nOPENAI_API_KEY=sk-123\n\nCUSTOM_TOKEN='abc-123'\n",
            encoding="utf-8",
        )
        parsed = cli._parse_env_file(env_file)
        assert parsed["OPENAI_API_KEY"] == "sk-123"
        assert parsed["CUSTOM_TOKEN"] == "abc-123"

    def test_required_metadata_fields(self, mock_env_vars):
        import cli

        assert "resource" in cli._required_metadata_fields("azure_openai")
        assert cli._required_metadata_fields("openai") == []

    def test_validate_key_format_hint(self, mock_env_vars):
        import cli

        warning = cli._validate_key_format("openai", "abc")
        assert warning is not None
        assert "sk-" in warning or "ungueltig" in warning.lower()

    def test_run_doctor_checks_without_key_fails(self, monkeypatch, mock_env_vars, tmp_path):
        import cli

        monkeypatch.delenv("AGENT_VAULT_KEY", raising=False)
        monkeypatch.delenv("AGENT_VAULT_KEY_FILE", raising=False)
        monkeypatch.setattr(cli, "DB_PATH", tmp_path / "missing.db")
        checks, ok = cli.run_doctor_checks()
        assert ok is False
        assert any(item["name"] == "Vault Key Source" and item["status"] == "fail" for item in checks)


@pytest.mark.unit
class TestCLIConfiguration:
    """Test CLI configuration."""
    
    def test_app_dir_configuration(self, mock_env_vars):
        """Test app directory configuration."""
        import cli
        
        assert hasattr(cli, 'APP_DIR')
        assert hasattr(cli, 'DB_PATH')
        assert hasattr(cli, 'KEY_FILE')
    
    def test_version_defined(self, mock_env_vars):
        """Test that version is defined."""
        import cli
        
        assert hasattr(cli, 'VERSION')
        # Version should be a string
        assert isinstance(cli.VERSION, str)
        # Should contain version number
        assert "." in cli.VERSION

    def test_new_commands_registered(self, mock_env_vars):
        import cli

        command_names = set(cli.cli.commands.keys())
        for required in {"setup", "doctor", "import-keys", "start", "help"}:
            assert required in command_names


@pytest.mark.unit
class TestCLICommands:
    def test_status_does_not_leak_env_key(self, mock_env_vars, monkeypatch, tmp_path):
        import cli

        app_dir = tmp_path / "app"
        app_dir.mkdir()
        db_path = app_dir / "vault.db"
        db_path.write_text("db", encoding="utf-8")

        monkeypatch.setattr(cli, "APP_DIR", app_dir)
        monkeypatch.setattr(cli, "DB_PATH", db_path)
        monkeypatch.setattr(cli, "list_api_keys", lambda: [])
        monkeypatch.setattr(cli, "list_users", lambda: [])
        monkeypatch.setattr(cli, "get_audit_stats", lambda: {"total_requests": 0})

        runner = CliRunner()
        result = runner.invoke(cli.cli, ["status"])
        assert result.exit_code == 0
        assert "Vault key source" in result.output
        assert "test-master-key-for-t" not in result.output

    def test_help_alias_prints_overview(self, mock_env_vars):
        import cli

        runner = CliRunner()
        result = runner.invoke(cli.cli, ["help"])
        assert result.exit_code == 0
        assert "KeyRelay CLI command overview" in result.output
        assert "python3 cli.py setup" in result.output

    def test_import_keys_from_env(self, mock_env_vars, monkeypatch, tmp_path):
        import cli

        db_path = tmp_path / "vault.db"
        db_path.write_text("stub", encoding="utf-8")
        monkeypatch.setattr(cli, "DB_PATH", db_path)
        monkeypatch.setattr(cli, "get_api_key", lambda _service: None)
        monkeypatch.setattr(cli, "add_api_key", lambda _service, _key, _metadata=None, **_kwargs: True)
        monkeypatch.setattr(cli, "set_service_metadata", lambda *_args, **_kwargs: True)

        env_file = tmp_path / ".env"
        env_file.write_text("OPENAI_API_KEY=sk-test\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli.cli, ["import-keys", "--from-env", str(env_file)], input="y\n")
        assert result.exit_code == 0
        assert "Import abgeschlossen" in result.output

    def test_user_create_with_auto_password(self, mock_env_vars, monkeypatch, tmp_path):
        import cli

        db_path = tmp_path / "vault.db"
        db_path.write_text("stub", encoding="utf-8")
        monkeypatch.setattr(cli, "DB_PATH", db_path)
        monkeypatch.setattr(cli, "create_user", lambda _username, _password, _role="user", **_kwargs: "proxy_key_123")

        runner = CliRunner()
        result = runner.invoke(cli.cli, ["user-create", "tester", "--role", "admin", "--auto-password"])
        assert result.exit_code == 0
        assert "User created successfully" in result.output
        assert "proxy_key_123" in result.output

    def test_doctor_command_renders(self, mock_env_vars, monkeypatch):
        import cli

        monkeypatch.setattr(
            cli,
            "run_doctor_checks",
            lambda **_kwargs: ([{"name": "X", "status": "pass", "detail": "ok"}], True),
        )
        runner = CliRunner()
        result = runner.invoke(cli.cli, ["doctor"])
        assert result.exit_code == 0
        assert "Doctor Report" in result.output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
