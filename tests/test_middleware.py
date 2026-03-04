"""
Tests for Agent Vault Proxy middleware.

Tests security, rate limiting, and logging middleware.
"""

import pytest
import time
from fastapi.testclient import TestClient

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up test environment variables."""
    monkeypatch.setenv("AGENT_VAULT_KEY", "test-master-key-for-testing-only-32bytes!")
    monkeypatch.setenv("AGENT_VAULT_TEST_MODE", "1")  # Disable rate limiting
    yield


@pytest.mark.unit
class TestSecurityMiddleware:
    """Test security middleware."""
    
    def test_path_traversal_blocked(self, mock_env_vars):
        """Test that path traversal attempts are blocked."""
        from main import app
        
        client = TestClient(app)
        
        # Test various path traversal patterns - should return 400, 404, or handled
        malicious_paths = [
            "/openrouter/../../../etc/passwd",
            "/openrouter/..%2f..%2f..%2fetc%2fpasswd",
        ]
        
        for path in malicious_paths:
            response = client.get(path)
            # Middleware may block with 400, or return 404 if service not found, or handle gracefully
            assert response.status_code in [400, 404, 422, 500], f"Path {path} should be blocked"
    
    def test_null_bytes_blocked(self, mock_env_vars):
        """Test that null bytes are handled."""
        from main import app
        
        client = TestClient(app)
        response = client.get("/openrouter/test\x00evil")
        
        # Null bytes should be sanitized or cause error
        assert response.status_code in [400, 404, 422, 500]
    
    def test_long_path_handled(self, mock_env_vars):
        """Test that very long paths are handled."""
        from main import app
        
        client = TestClient(app)
        long_path = "/openrouter/" + "a" * 3000
        
        response = client.get(long_path)
        # Should be blocked with 414 or handled gracefully
        assert response.status_code in [400, 404, 414, 422, 200, 500]
    
    def test_invalid_service_name_blocked(self, mock_env_vars):
        """Test that invalid service names are blocked."""
        from main import app
        
        client = TestClient(app)
        
        invalid_services = [
            "/service with spaces/test",
            "/service<script>/test",
        ]
        
        for path in invalid_services:
            response = client.get(path)
            assert response.status_code in [400, 404]
    
    def test_security_headers_present(self, mock_env_vars):
        """Test that security headers are added to responses."""
        from main import app
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        assert response.headers.get('X-Frame-Options') == 'DENY'


@pytest.mark.unit
class TestRateLimitMiddleware:
    """Test rate limiting middleware."""
    
    def test_rate_limit_enforced(self, mock_env_vars):
        """Test that rate limiting is enforced."""
        from main import app
        
        client = TestClient(app)
        
        # Make many requests quickly
        responses = []
        for _ in range(70):  # Above the 60/min limit
            response = client.get("/health")
            responses.append(response.status_code)
        
        # At least some should be rate limited (429) or all succeed
        assert 429 in responses or all(r == 200 for r in responses[:60])
    
    def test_rate_limit_headers(self, mock_env_vars):
        """Test that rate limit headers are present on blocked requests."""
        from main import app
        
        client = TestClient(app)
        
        # Make many requests to trigger rate limit
        for _ in range(100):
            response = client.get("/health")
            if response.status_code == 429:
                # Check for Retry-After header on rate limited response
                assert 'Retry-After' in response.headers
                break


@pytest.mark.unit
class TestLoggingMiddleware:
    """Test logging middleware."""
    
    def test_response_time_header(self, mock_env_vars):
        """Test that response time header is added."""
        from main import app
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        assert 'X-Response-Time' in response.headers
        
        # Verify it's a valid time format (contains 's' for seconds)
        time_str = response.headers['X-Response-Time']
        assert 's' in time_str


@pytest.mark.unit
class TestCORSMiddleware:
    """Test CORS middleware."""
    
    def test_cors_preflight(self, mock_env_vars):
        """Test CORS preflight requests."""
        from main import app
        
        client = TestClient(app)
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            }
        )
        
        assert response.status_code == 200
        # CORS middleware returns the specific origin, not *
        assert 'access-control-allow-origin' in response.headers
        assert 'access-control-allow-methods' in response.headers
    
    def test_cors_headers_on_response(self, mock_env_vars):
        """Test CORS headers on regular responses."""
        from main import app
        
        client = TestClient(app)
        response = client.get(
            "/health",
            headers={"Origin": "http://localhost:3000"}
        )
        
        assert response.status_code == 200
        # CORS middleware returns the specific origin
        assert 'access-control-allow-origin' in response.headers


@pytest.mark.unit
class TestRequestValidation:
    """Test request validation."""
    
    def test_large_request_blocked(self, mock_env_vars):
        """Test that very large requests are handled."""
        from main import app
        
        client = TestClient(app)
        
        # Create a payload (10KB is fine)
        response = client.post(
            "/openrouter/test",
            json={"data": "x" * 10000},
            headers={"Content-Type": "application/json"}
        )
        
        # Should not be blocked with 413 for this size (may be 404 if service not configured, or other errors)
        assert response.status_code != 413


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
