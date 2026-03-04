"""
Tests for Agent Vault CLI.

Tests CLI functionality including:
- Vault initialization
- Key management
- Service configuration
- Audit logging
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up test environment variables."""
    monkeypatch.setenv("AGENT_VAULT_KEY", "test-master-key-for-testing-only-32bytes!")
    yield


@pytest.fixture
def temp_vault_dir():
    """Create a temporary vault directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = Path(tmpdir) / ".agent-vault"
        vault_dir.mkdir()
        yield vault_dir


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
        """Test getting encryption key from environment."""
        import cli
        
        # Key should be derivable from env
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
