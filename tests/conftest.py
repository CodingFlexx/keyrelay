"""
Pytest configuration and fixtures for Agent Vault Proxy tests.
"""

import os
import sys
import pytest
import asyncio
from pathlib import Path
from typing import AsyncGenerator, Generator
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from fastapi.testclient import TestClient

# Test configuration
TEST_DB_PATH = Path("/tmp/test_vault.db")
TEST_KEY_FILE = Path("/tmp/test_master_key")


def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line("markers", "asyncio: mark test as async")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "unit: mark test as unit test")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
def mock_env_vars(monkeypatch):
    """Set up environment variables for testing."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("PINECONE_API_KEY", "test-pinecone-key")
    monkeypatch.setenv("GITHUB_PAT", "test-github-pat")
    monkeypatch.setenv("BRAVE_API_KEY", "test-brave-key")


@pytest.fixture(scope="function")
def temp_vault_dir(tmp_path):
    """Create a temporary vault directory for testing."""
    vault_dir = tmp_path / ".agent-vault"
    vault_dir.mkdir(mode=0o700)
    
    # Create test master key
    import base64
    from cryptography.fernet import Fernet
    
    key = Fernet.generate_key()
    key_file = vault_dir / ".master_key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    
    # Create test database
    import sqlite3
    db_path = vault_dir / "vault.db"
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
    
    # Insert test encrypted keys
    cipher = Fernet(key)
    
    test_keys = [
        ("openrouter", cipher.encrypt(b"test-openrouter-key").decode()),
        ("openai", cipher.encrypt(b"test-openai-key").decode()),
        ("anthropic", cipher.encrypt(b"test-anthropic-key").decode()),
        ("github", cipher.encrypt(b"test-github-pat").decode()),
    ]
    
    cursor.executemany(
        'INSERT INTO api_keys (service, key_value) VALUES (?, ?)',
        test_keys
    )
    
    conn.commit()
    conn.close()
    db_path.chmod(0o600)
    
    return vault_dir


@pytest.fixture(scope="function")
def mock_secrets():
    """Return mock secrets dictionary."""
    return {
        "openrouter": {"api_key": "test-openrouter-key"},
        "openai": {"api_key": "test-openai-key"},
        "anthropic": {"api_key": "test-anthropic-key"},
        "github": {"pat": "test-github-pat"},
        "pinecone": {"api_key": "test-pinecone-key"},
    }


@pytest.fixture(scope="function")
async def async_http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an async HTTP client for testing."""
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture(scope="function")
def mock_httpx_response():
    """Create a mock httpx response."""
    def _create_mock(status_code=200, json_data=None, text="", headers=None):
        mock = Mock()
        mock.status_code = status_code
        mock.json.return_value = json_data or {}
        mock.text = text
        mock.content = text.encode() if text else b""
        mock.headers = headers or {"content-type": "application/json"}
        return mock
    return _create_mock


@pytest.fixture(scope="function")
def mock_circuit_breaker():
    """Create a mock circuit breaker."""
    cb = Mock()
    cb.is_open.return_value = False
    cb.record_success = Mock()
    cb.record_failure = Mock()
    return cb


@pytest.fixture(scope="function")
def mock_rate_limiter():
    """Create a mock rate limiter."""
    rl = Mock()
    rl.is_allowed.return_value = True
    rl.get_wait_time.return_value = 0
    return rl


@pytest.fixture(scope="function")
def mock_cache():
    """Create a mock cache."""
    cache = Mock()
    cache.get.return_value = None
    cache.set = Mock()
    cache.delete = Mock()
    return cache


@pytest.fixture(scope="session")
def test_services_config():
    """Return test configuration for services."""
    return {
        "openrouter": {
            "base_url": "https://openrouter.ai/api/v1",
            "auth_type": "bearer",
            "rate_limit": 100,
            "timeout": 30,
        },
        "openai": {
            "base_url": "https://api.openai.com/v1",
            "auth_type": "bearer",
            "rate_limit": 60,
            "timeout": 60,
        },
        "github": {
            "base_url": "https://api.github.com",
            "auth_type": "token",
            "rate_limit": 5000,
            "timeout": 30,
        },
    }


@pytest.fixture(scope="function")
def sample_request_data():
    """Return sample request data for testing."""
    return {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}],
        "temperature": 0.7,
    }


@pytest.fixture(scope="function")
def sample_response_data():
    """Return sample response data for testing."""
    return {
        "id": "test-response-id",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "gpt-4",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello!"},
            "finish_reason": "stop"
        }],
    }


@pytest.fixture(scope="function")
def auth_headers():
    """Return sample authentication headers."""
    return {
        "Authorization": "Bearer test-token",
        "Content-Type": "application/json",
        "X-Request-ID": "test-request-123",
    }


@pytest.fixture(scope="function")
def clean_test_files():
    """Clean up test files after each test."""
    yield
    # Cleanup
    for path in [TEST_DB_PATH, TEST_KEY_FILE]:
        if path.exists():
            path.unlink()


# Pytest hooks for custom reporting
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Add custom summary to test report."""
    terminalreporter.write_sep("=", "Agent Vault Proxy Test Summary")
    
    passed = len(terminalreporter.stats.get('passed', []))
    failed = len(terminalreporter.stats.get('failed', []))
    skipped = len(terminalreporter.stats.get('skipped', []))
    
    terminalreporter.write_line(f"Passed: {passed}")
    terminalreporter.write_line(f"Failed: {failed}")
    terminalreporter.write_line(f"Skipped: {skipped}")
    terminalreporter.write_line(f"Total: {passed + failed + skipped}")
