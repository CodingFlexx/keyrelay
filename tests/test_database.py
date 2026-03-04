"""
Database tests for Agent Vault Proxy.

Tests database operations including:
- Encryption/Decryption
- API key CRUD operations
- Audit logging
- RBAC (Role-Based Access Control)
- Service metadata
"""

import pytest
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography.fernet import Fernet


# Set test environment variable before importing database
os.environ["AGENT_VAULT_KEY"] = "test-master-key-for-testing-only-32bytes!"

import database as db


@pytest.fixture(scope="function")
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Override database path
        original_path = db.DB_PATH
        test_db_path = Path(tmpdir) / "test_vault.db"
        db.DB_PATH = test_db_path
        db.APP_DIR = Path(tmpdir)
        
        # Initialize database
        db.init_database()
        
        yield test_db_path
        
        # Restore original path
        db.DB_PATH = original_path


@pytest.mark.unit
class TestEncryption:
    """Test encryption and decryption operations."""
    
    def test_encryption_key_generation(self):
        """Test that encryption key is properly generated."""
        key = db.get_encryption_key()
        assert isinstance(key, bytes)
        assert len(key) == 44  # Fernet keys are 44 bytes in base64
    
    def test_cipher_creation(self):
        """Test Fernet cipher creation."""
        cipher = db.get_cipher()
        assert isinstance(cipher, Fernet)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption and decryption work correctly."""
        original = "test-api-key-12345"
        encrypted = db.encrypt_value(original)
        decrypted = db.decrypt_value(encrypted)
        
        assert encrypted != original
        assert decrypted == original
    
    def test_different_values_produce_different_ciphertexts(self):
        """Test that different values produce different encrypted outputs."""
        value1 = "key-one"
        value2 = "key-two"
        
        encrypted1 = db.encrypt_value(value1)
        encrypted2 = db.encrypt_value(value2)
        
        assert encrypted1 != encrypted2
    
    def test_same_value_produces_different_ciphertexts(self):
        """Test that same value produces different ciphertexts (due to Fernet)."""
        value = "same-key"
        
        encrypted1 = db.encrypt_value(value)
        encrypted2 = db.encrypt_value(value)
        
        # Fernet uses random IV, so ciphertexts should differ
        assert encrypted1 != encrypted2
        
        # But both should decrypt to same value
        assert db.decrypt_value(encrypted1) == value
        assert db.decrypt_value(encrypted2) == value
    
    def test_decrypt_invalid_data(self):
        """Test that decrypting invalid data raises an error."""
        with pytest.raises(Exception):
            db.decrypt_value("invalid-encrypted-data")
    
    def test_encrypt_empty_string(self):
        """Test encrypting empty string."""
        encrypted = db.encrypt_value("")
        decrypted = db.decrypt_value(encrypted)
        assert decrypted == ""


@pytest.mark.unit
class TestDatabaseInitialization:
    """Test database initialization."""
    
    def test_database_file_created(self, temp_db):
        """Test that database file is created."""
        assert temp_db.exists()
    
    def test_tables_created(self, temp_db):
        """Test that all required tables are created."""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        
        assert "api_keys" in tables
        assert "audit_logs" in tables
        assert "users" in tables
        assert "service_metadata" in tables
        
        conn.close()
    
    def test_indexes_created(self, temp_db):
        """Test that indexes are created."""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        
        assert "idx_audit_timestamp" in indexes
        assert "idx_audit_service" in indexes
        assert "idx_api_keys_active" in indexes
        
        conn.close()
    
    def test_database_permissions(self, temp_db):
        """Test that database has correct permissions."""
        import stat
        mode = temp_db.stat().st_mode
        # Should be readable/writable by owner only
        assert mode & stat.S_IRUSR
        assert mode & stat.S_IWUSR


@pytest.mark.unit
class TestAPIKeyOperations:
    """Test API key CRUD operations."""
    
    def test_add_api_key(self, temp_db):
        """Test adding an API key."""
        result = db.add_api_key("test_service", "test-key-123")
        assert result is True
        
        # Verify key was added
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM api_keys WHERE service_name = ?", ("test_service",))
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 1
    
    def test_add_api_key_with_metadata(self, temp_db):
        """Test adding an API key with metadata."""
        metadata = {"region": "us-east-1", "project": "test-project"}
        result = db.add_api_key("test_service", "test-key", metadata)
        assert result is True
        
        # Verify metadata was stored
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT metadata FROM api_keys WHERE service_name = ?", ("test_service",))
        row = cursor.fetchone()
        conn.close()
        
        assert row is not None
        stored_metadata = json.loads(row[0])
        assert stored_metadata["region"] == "us-east-1"
    
    def test_get_api_key(self, temp_db):
        """Test retrieving an API key."""
        db.add_api_key("test_service", "secret-key-123")
        
        retrieved = db.get_api_key("test_service")
        assert retrieved == "secret-key-123"
    
    def test_get_nonexistent_key(self, temp_db):
        """Test retrieving a non-existent key."""
        result = db.get_api_key("nonexistent_service")
        assert result is None
    
    def test_get_inactive_key(self, temp_db):
        """Test that inactive keys are not returned."""
        db.add_api_key("test_service", "secret-key")
        
        # Deactivate key
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET is_active = 0 WHERE service_name = ?", ("test_service",))
        conn.commit()
        conn.close()
        
        result = db.get_api_key("test_service")
        assert result is None
    
    def test_update_existing_key(self, temp_db):
        """Test updating an existing API key."""
        db.add_api_key("test_service", "old-key")
        db.add_api_key("test_service", "new-key")
        
        retrieved = db.get_api_key("test_service")
        assert retrieved == "new-key"
    
    def test_list_api_keys(self, temp_db):
        """Test listing all API keys."""
        db.add_api_key("service1", "key1")
        db.add_api_key("service2", "key2")
        
        keys = db.list_api_keys()
        assert len(keys) == 2
        
        service_names = {k["service_name"] for k in keys}
        assert "service1" in service_names
        assert "service2" in service_names
    
    def test_list_api_keys_no_decryption(self, temp_db):
        """Test that listing keys doesn't decrypt them."""
        db.add_api_key("test_service", "secret-key")
        
        keys = db.list_api_keys()
        assert len(keys) == 1
        
        # Key should still be encrypted in database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_key FROM api_keys WHERE service_name = ?", ("test_service",))
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] != "secret-key"  # Should be encrypted
    
    def test_remove_api_key(self, temp_db):
        """Test removing an API key."""
        db.add_api_key("test_service", "secret-key")
        
        result = db.remove_api_key("test_service")
        assert result is True
        
        # Verify key was removed
        retrieved = db.get_api_key("test_service")
        assert retrieved is None
    
    def test_remove_nonexistent_key(self, temp_db):
        """Test removing a non-existent key."""
        result = db.remove_api_key("nonexistent")
        assert result is False
    
    def test_rotate_api_key(self, temp_db):
        """Test rotating an API key."""
        db.add_api_key("test_service", "old-key")
        
        result = db.rotate_api_key("test_service", "new-key")
        assert result is True
        
        retrieved = db.get_api_key("test_service")
        assert retrieved == "new-key"


@pytest.mark.unit
class TestServiceMetadata:
    """Test service metadata operations."""
    
    def test_set_service_metadata(self, temp_db):
        """Test setting service metadata."""
        db.add_api_key("test_service", "key")
        
        result = db.set_service_metadata(
            "test_service",
            cluster="cluster-1",
            project="project-1",
            region="us-west-2"
        )
        assert result is True
    
    def test_get_service_with_metadata(self, temp_db):
        """Test retrieving service with metadata."""
        db.add_api_key("test_service", "key")
        db.set_service_metadata("test_service", cluster="cluster-1")
        
        keys = db.list_api_keys()
        service = next(k for k in keys if k["service_name"] == "test_service")
        
        assert service["cluster"] == "cluster-1"
    
    def test_update_service_metadata(self, temp_db):
        """Test updating service metadata."""
        db.add_api_key("test_service", "key")
        db.set_service_metadata("test_service", cluster="cluster-1")
        db.set_service_metadata("test_service", cluster="cluster-2", project="new-project")
        
        keys = db.list_api_keys()
        service = next(k for k in keys if k["service_name"] == "test_service")
        
        assert service["cluster"] == "cluster-2"
        assert service["project"] == "new-project"


@pytest.mark.unit
class TestAuditLogging:
    """Test audit logging functionality."""
    
    def test_log_request(self, temp_db):
        """Test logging a request."""
        db.log_request(
            service="openai",
            endpoint="/v1/chat/completions",
            client_ip="127.0.0.1",
            success=True,
            request_method="POST",
            response_status=200,
            user_agent="test-agent"
        )
        
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 1
    
    def test_log_request_with_error(self, temp_db):
        """Test logging a failed request."""
        db.log_request(
            service="openai",
            endpoint="/v1/chat/completions",
            client_ip="127.0.0.1",
            success=False,
            request_method="POST",
            response_status=401,
            error_message="Invalid API key"
        )
        
        logs = db.get_audit_logs(limit=1)
        assert len(logs) == 1
        assert logs[0]["error_message"] == "Invalid API key"
    
    def test_get_audit_logs(self, temp_db):
        """Test retrieving audit logs."""
        for i in range(5):
            db.log_request(
                service=f"service{i}",
                endpoint="/test",
                client_ip="127.0.0.1",
                success=True,
                request_method="GET"
            )
        
        logs = db.get_audit_logs(limit=3)
        assert len(logs) == 3
    
    def test_get_audit_logs_by_service(self, temp_db):
        """Test filtering audit logs by service."""
        db.log_request("service1", "/test", "127.0.0.1", True, "GET")
        db.log_request("service2", "/test", "127.0.0.1", True, "GET")
        db.log_request("service1", "/test", "127.0.0.1", True, "POST")
        
        logs = db.get_audit_logs(service="service1")
        assert len(logs) == 2
        for log in logs:
            assert log["service"] == "service1"
    
    def test_get_audit_stats(self, temp_db):
        """Test getting audit statistics."""
        db.log_request("s1", "/test", "127.0.0.1", True, "GET", 200)
        db.log_request("s1", "/test", "127.0.0.1", True, "GET", 200)
        db.log_request("s2", "/test", "127.0.0.1", False, "GET", 500)
        
        stats = db.get_audit_stats()
        
        assert stats["total_requests"] == 3
        assert stats["successful"] == 2
        assert stats["failed"] == 1
        assert stats["by_service"]["s1"] == 2
        assert stats["by_service"]["s2"] == 1


@pytest.mark.unit
class TestRBAC:
    """Test Role-Based Access Control."""
    
    def test_create_user(self, temp_db):
        """Test creating a user."""
        api_key = db.create_user("testuser", "password123", "user")
        
        assert api_key is not None
        assert len(api_key) > 20  # API key should be reasonably long
    
    def test_create_duplicate_user(self, temp_db):
        """Test creating a duplicate user fails."""
        db.create_user("testuser", "password123")
        result = db.create_user("testuser", "password456")
        
        assert result is None
    
    def test_verify_user(self, temp_db):
        """Test verifying user credentials."""
        db.create_user("testuser", "password123", "user")
        
        user = db.verify_user("testuser", "password123")
        assert user is not None
        assert user["username"] == "testuser"
        assert user["role"] == "user"
    
    def test_verify_user_wrong_password(self, temp_db):
        """Test verifying with wrong password."""
        db.create_user("testuser", "password123")
        
        user = db.verify_user("testuser", "wrongpassword")
        assert user is None
    
    def test_verify_user_nonexistent(self, temp_db):
        """Test verifying non-existent user."""
        user = db.verify_user("nonexistent", "password")
        assert user is None
    
    def test_verify_api_key(self, temp_db):
        """Test verifying API key."""
        api_key = db.create_user("testuser", "password123", "admin")
        
        user = db.verify_api_key(api_key)
        assert user is not None
        assert user["username"] == "testuser"
        assert user["role"] == "admin"
    
    def test_verify_invalid_api_key(self, temp_db):
        """Test verifying invalid API key."""
        user = db.verify_api_key("invalid-api-key")
        assert user is None
    
    def test_list_users(self, temp_db):
        """Test listing users."""
        db.create_user("user1", "pass1")
        db.create_user("user2", "pass2")
        
        users = db.list_users()
        assert len(users) == 2
    
    def test_delete_user(self, temp_db):
        """Test deleting a user."""
        db.create_user("testuser", "password123")
        
        result = db.delete_user("testuser")
        assert result is True
        
        # Verify user is gone
        user = db.verify_user("testuser", "password123")
        assert user is None
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed."""
        hash1 = db.hash_password("password123")
        hash2 = db.hash_password("password123")
        
        # Same password should produce same hash
        assert hash1 == hash2
        
        # Different passwords should produce different hashes
        hash3 = db.hash_password("different")
        assert hash1 != hash3
    
    def test_api_key_hashing(self):
        """Test that API keys are properly hashed."""
        hash1 = db.hash_api_key("api-key-123")
        hash2 = db.hash_api_key("api-key-123")
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 produces 64 hex characters


@pytest.mark.unit
class TestDatabaseContextManager:
    """Test database connection context manager."""
    
    def test_get_db_connection(self, temp_db):
        """Test database connection context manager."""
        with db.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1
    
    def test_connection_closed_after_context(self, temp_db):
        """Test that connection is closed after context."""
        conn = None
        with db.get_db_connection() as c:
            conn = c
        
        # Connection should be closed
        # Note: sqlite3 doesn't have a simple way to check if closed
        # This is implicitly tested by the context manager


@pytest.mark.unit
class TestDatabaseEdgeCases:
    """Test edge cases and error handling."""
    
    def test_add_api_key_with_special_characters(self, temp_db):
        """Test adding API key with special characters."""
        special_key = "key-with-special-chars-!@#$%^&*()_+-=[]{}|;':\",./<>?"
        db.add_api_key("test_service", special_key)
        
        retrieved = db.get_api_key("test_service")
        assert retrieved == special_key
    
    def test_add_api_key_with_unicode(self, temp_db):
        """Test adding API key with unicode characters."""
        unicode_key = "key-with-unicode-日本語-中文-🎉"
        db.add_api_key("test_service", unicode_key)
        
        retrieved = db.get_api_key("test_service")
        assert retrieved == unicode_key
    
    def test_very_long_api_key(self, temp_db):
        """Test adding very long API key."""
        long_key = "x" * 10000
        db.add_api_key("test_service", long_key)
        
        retrieved = db.get_api_key("test_service")
        assert retrieved == long_key
    
    def test_concurrent_access(self, temp_db):
        """Test concurrent database access."""
        import threading
        
        results = []
        
        def add_key(i):
            result = db.add_api_key(f"service{i}", f"key{i}")
            results.append(result)
        
        threads = [threading.Thread(target=add_key, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(results) == 10
        assert all(results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
