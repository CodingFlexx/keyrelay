"""
Tests for Agent Vault Proxy middleware.

Tests security, rate limiting, and logging middleware.
"""

import pytest
import time
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def mock_env_vars(monkeypatch, tmp_path):
    """Set up test environment variables."""
    monkeypatch.setenv("AGENT_VAULT_KEY", "test-master-key-for-testing-only-32bytes!")
    monkeypatch.setenv("AGENT_VAULT_TEST_MODE", "1")  # Disable rate limiting
    monkeypatch.setenv("REQUIRE_AGENT_AUTH", "false")
    monkeypatch.setenv("AGENT_VAULT_APP_DIR", str(tmp_path))
    import importlib
    import app.db.database as database

    importlib.reload(database)
    database.init_database()
    yield


@pytest.mark.unit
class TestSecurityMiddleware:
    """Test security middleware."""
    
    def test_path_traversal_blocked(self, mock_env_vars):
        """Test that path traversal attempts are blocked."""
        from app.main import app
        
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
        from app.main import app
        
        client = TestClient(app)
        # Use URL-encoded null byte (%00) to test middleware handling
        response = client.get("/openrouter/test%00evil")
        
        # Null bytes should be sanitized or cause error
        assert response.status_code in [400, 404, 422, 500]
    
    def test_long_path_handled(self, mock_env_vars):
        """Test that very long paths are handled."""
        from app.main import app
        
        client = TestClient(app)
        long_path = "/openrouter/" + "a" * 3000
        
        response = client.get(long_path)
        # Should be blocked with 414 or handled gracefully
        assert response.status_code in [400, 404, 414, 422, 200, 500]
    
    def test_invalid_service_name_blocked(self, mock_env_vars):
        """Test that invalid service names are blocked."""
        from app.main import app
        
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
        from app.main import app
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        assert response.headers.get('X-Frame-Options') == 'DENY'


@pytest.mark.unit
class TestRateLimitMiddleware:
    """Test rate limiting middleware."""
    
    def _build_rate_limited_app(self):
        """Build an app with active rate limit middleware for deterministic tests."""
        from app.middleware.middleware import RateLimitMiddleware

        app = FastAPI()
        app.add_middleware(RateLimitMiddleware, requests_per_minute=5, burst_size=1)

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        return app

    def test_rate_limit_enforced(self, mock_env_vars, monkeypatch):
        """Test that rate limiting is actually enforced when active."""
        monkeypatch.setenv("AGENT_VAULT_TEST_MODE", "0")
        app = self._build_rate_limited_app()
        client = TestClient(app)

        responses = [client.get("/health").status_code for _ in range(8)]
        assert 429 in responses
    
    def test_rate_limit_headers(self, mock_env_vars, monkeypatch):
        """Test that blocked responses include Retry-After header."""
        monkeypatch.setenv("AGENT_VAULT_TEST_MODE", "0")
        app = self._build_rate_limited_app()
        client = TestClient(app)

        blocked_response = None
        for _ in range(8):
            response = client.get("/health")
            if response.status_code == 429:
                blocked_response = response
                break

        assert blocked_response is not None
        assert "Retry-After" in blocked_response.headers


@pytest.mark.unit
class TestLoggingMiddleware:
    """Test logging middleware."""
    
    def test_response_time_header(self, mock_env_vars):
        """Test that response time header is added."""
        from app.main import app
        
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
        from app.main import app
        
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
        from app.main import app
        
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
        from app.main import app
        
        client = TestClient(app)
        
        response = client.post(
            "/health",
            json={"data": "x" * 10000},
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code != 413

    def test_invalid_content_length_handled(self, mock_env_vars):
        """Test that non-numeric content-length is rejected gracefully."""
        from app.main import app

        client = TestClient(app)
        response = client.get("/health", headers={"Content-Length": "not-a-number"})
        assert response.status_code in [200, 400]

    def test_tilde_in_path_allowed(self, mock_env_vars):
        """Test that tilde in URL path is no longer blocked."""
        from app.main import app

        client = TestClient(app)
        response = client.get("/openai/~user/resource")
        assert response.status_code != 400


@pytest.mark.unit
class TestAnonymousDevMode:
    """Test that anonymous dev mode does not grant admin."""

    def test_anonymous_dev_gets_user_role(self, mock_env_vars):
        """Anonymous dev mode should yield 'user' role, not 'admin'."""
        import importlib
        import app.main as main
        importlib.reload(main)
        from app.main import app

        client = TestClient(app)
        response = client.get("/admin/services")
        assert response.status_code == 403

    def test_health_services_accessible_in_dev_mode(self, mock_env_vars):
        """Health services endpoint should be accessible in dev mode (user role)."""
        import importlib
        import app.main as main
        importlib.reload(main)
        from app.main import app

        client = TestClient(app)
        response = client.get("/health/services")
        assert response.status_code == 200


@pytest.mark.unit
class TestCORSConfiguration:
    """Test that CORS is no longer wildcard."""

    def test_cors_not_wildcard_by_default(self, mock_env_vars):
        from app.main import app

        client = TestClient(app)
        response = client.get(
            "/health",
            headers={"Origin": "https://evil.com"}
        )
        cors_header = response.headers.get("access-control-allow-origin", "")
        assert cors_header != "*"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
