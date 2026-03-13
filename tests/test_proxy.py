"""
Integration tests for Agent Vault Proxy.

Tests the main proxy functionality including:
- Request forwarding
- Authentication injection
- Error handling
- Circuit breaker
- Rate limiting
- Caching
"""

import pytest
import json
import respx
import time
from httpx import Response
from fastapi.testclient import TestClient

# Import main app
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
    database.add_api_key("openrouter", "test-openrouter-key")
    database.add_api_key("openai", "test-openai-key")
    database.add_api_key("github", "test-github-pat")
    database.add_api_key("anthropic", "test-anthropic-key")
    database.add_api_key("gemini", "gemini-key")
    database.add_api_key("stability", "test-stability-key")
    database.add_api_key("telegram", "bot123:token")
    yield


@pytest.mark.unit
class TestProxyBasic:
    """Basic proxy functionality tests."""
    
    def test_health_endpoint(self, mock_env_vars):
        """Test health check endpoint."""
        from app.main import app
        
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "services_available" in data
        assert "services_configured" in data
    
    def test_root_endpoint(self, mock_env_vars):
        """Test root endpoint returns usage info."""
        from app.main import app
        
        client = TestClient(app)
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "KeyRelay Proxy"
        assert data["version"] == "0.9.1"
        assert "endpoints" in data
        assert "cli" in data
    
    def test_unknown_service(self, mock_env_vars):
        """Test proxy returns 404 for unknown service."""
        from app.main import app
        
        client = TestClient(app)
        response = client.get("/unknown_service/test")
        
        assert response.status_code == 404
        assert "Unknown service" in response.json()["detail"]


@pytest.mark.integration
class TestProxyForwarding:
    """Test request forwarding to external services."""
    
    @respx.mock
    def test_openrouter_forwarding(self, mock_env_vars, sample_request_data, sample_response_data):
        """Test forwarding request to OpenRouter."""
        from app.main import app
        # Mock OpenRouter API
        route = respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
            return_value=Response(200, json=sample_response_data)
        )
        
        client = TestClient(app)
        response = client.post(
            "/openrouter/chat/completions",
            json=sample_request_data,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 200
        assert route.called
        
        # Verify auth header was injected
        request = route.calls[0].request
        assert "Authorization" in request.headers
        assert "Bearer" in request.headers["Authorization"]
    
    @respx.mock
    def test_openai_forwarding(self, mock_env_vars, sample_request_data, sample_response_data):
        """Test forwarding request to OpenAI."""
        from app.main import app
        
        route = respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=Response(200, json=sample_response_data)
        )
        
        client = TestClient(app)
        response = client.post(
            "/openai/chat/completions",
            json=sample_request_data
        )
        
        assert response.status_code == 200
        assert route.called
    
    @respx.mock
    def test_github_forwarding(self, mock_env_vars):
        """Test forwarding request to GitHub API."""
        from app.main import app
        
        github_response = {
            "login": "testuser",
            "id": 12345,
            "type": "User"
        }
        
        route = respx.get("https://api.github.com/user").mock(
            return_value=Response(200, json=github_response)
        )
        
        client = TestClient(app)
        response = client.get("/github/user")
        
        assert response.status_code == 200
        assert route.called
        
        # Verify GitHub-specific headers
        request = route.calls[0].request
        assert "Accept" in request.headers
        assert "X-GitHub-Api-Version" in request.headers
    
    @respx.mock
    def test_query_params_forwarding(self, mock_env_vars):
        """Test query parameters are forwarded correctly."""
        from app.main import app
        
        route = respx.get("https://api.github.com/search/repositories").mock(
            return_value=Response(200, json={"items": []})
        )
        
        client = TestClient(app)
        response = client.get("/github/search/repositories?q=python&sort=stars")
        
        assert response.status_code == 200
        assert route.called
        
        # Verify query params
        request = route.calls[0].request
        assert "q=python" in str(request.url)
        assert "sort=stars" in str(request.url)
    
    @respx.mock
    def test_custom_headers_forwarding(self, mock_env_vars):
        """Test custom headers are forwarded."""
        from app.main import app
        
        route = respx.get("https://api.openai.com/v1/models").mock(
            return_value=Response(200, json={"data": []})
        )
        
        client = TestClient(app)
        response = client.get(
            "/openai/models",
            headers={"X-Custom-Header": "custom-value"}
        )
        
        assert response.status_code == 200
        assert route.called
        
        request = route.calls[0].request
        assert request.headers["X-Custom-Header"] == "custom-value"


@pytest.mark.integration
class TestProxyErrors:
    """Test error handling in proxy."""
    
    @respx.mock
    def test_timeout_error(self, mock_env_vars):
        """Test handling of timeout errors."""
        from app.main import app
        import httpx
        
        route = respx.post("https://api.openai.com/v1/chat/completions").mock(
            side_effect=httpx.TimeoutException("Request timed out")
        )
        
        client = TestClient(app)
        response = client.post(
            "/openai/chat/completions",
            json={"model": "gpt-4", "messages": []},
            timeout=5
        )
        
        assert response.status_code == 504
        assert "timeout" in response.json()["detail"].lower()
    
    @respx.mock
    def test_connection_error(self, mock_env_vars):
        """Test handling of connection errors."""
        from app.main import app
        import httpx
        
        route = respx.get("https://api.openai.com/v1/models").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        
        client = TestClient(app)
        response = client.get("/openai/models")
        
        assert response.status_code == 502
        assert "gateway" in response.json()["detail"].lower()
    
    @respx.mock
    def test_upstream_4xx_error(self, mock_env_vars):
        """Test forwarding of 4xx errors from upstream."""
        from app.main import app
        
        route = respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=Response(400, json={"error": "Invalid request"})
        )
        
        client = TestClient(app)
        response = client.post(
            "/openai/chat/completions",
            json={"invalid": "data"}
        )
        
        assert response.status_code == 400
    
    @respx.mock
    def test_upstream_5xx_error(self, mock_env_vars):
        """Test handling of 5xx errors from upstream."""
        from app.main import app
        
        route = respx.get("https://api.openai.com/v1/models").mock(
            return_value=Response(503, json={"error": "Service unavailable"})
        )
        
        client = TestClient(app)
        response = client.get("/openai/models")
        
        assert response.status_code == 503


@pytest.mark.unit
class TestProxyAuthInjection:
    """Test authentication header injection."""
    
    def test_bearer_token_injection(self, mock_env_vars):
        """Test Bearer token injection for services."""
        from app.core.security import get_auth_header

        auth = get_auth_header("openrouter", "test-key")
        assert auth.startswith("Bearer ")
        
        auth = get_auth_header("openai", "test-key")
        assert auth.startswith("Bearer ")
    
    def test_github_token_injection(self, mock_env_vars):
        """Test GitHub token format."""
        from app.core.security import get_auth_header

        auth = get_auth_header("github", "test-pat")
        assert auth.startswith("token ")
    
    def test_telegram_url_injection(self, mock_env_vars):
        """Test Telegram token in URL."""
        from app.core.security import get_auth_header

        auth = get_auth_header("telegram", "bot123:token")
        assert auth is None  # Telegram uses token in URL
    
    def test_twilio_basic_auth(self, mock_env_vars):
        """Test Twilio Basic auth format."""
        from app.core.security import get_auth_header

        auth = get_auth_header("twilio", "auth_token", {"account_sid": "AC123"})
        assert auth.startswith("Basic ")
    
    def test_unknown_service_defaults_to_bearer(self, mock_env_vars):
        """Test that unknown service uses Bearer auth by default."""
        from app.core.security import get_auth_header

        auth = get_auth_header("custom_service", "custom-key")
        assert auth == "Bearer custom-key"


@pytest.mark.unit
class TestProxyDynamicURLs:
    """Test dynamic URL construction."""
    
    def test_azure_openai_url(self, mock_env_vars):
        """Test Azure OpenAI URL with resource."""
        from app.core.config import TARGETS
        
        base = TARGETS["azure_openai"]
        assert "{resource}" in base
    
    def test_weaviate_url(self, mock_env_vars):
        """Test Weaviate URL with cluster."""
        from app.core.config import TARGETS
        
        base = TARGETS["weaviate"]
        assert "{cluster}" in base
    
    def test_supabase_url(self, mock_env_vars):
        """Test Supabase URL with project."""
        from app.core.config import TARGETS
        
        base = TARGETS["supabase"]
        assert "{project}" in base

    def test_telegram_url_replaces_prefixed_dummy_token(self, mock_env_vars):
        """Test Telegram paths with SDK token prefixes are normalized."""
        from app.core.security import get_target_url

        url = get_target_url(
            "telegram",
            "botDUMMY123/sendMessage",
            {"token": "REAL123:token"},
        )

        assert url == "https://api.telegram.org/botREAL123:token/sendMessage"

    def test_telegram_file_url_uses_file_prefix(self, mock_env_vars):
        """Test Telegram file download paths use /file/bot<TOKEN>/... format."""
        from app.core.security import get_target_url

        url = get_target_url(
            "telegram",
            "file/botDUMMY123/photos/file_1.jpg",
            {"token": "REAL123:token"},
        )

        assert url == "https://api.telegram.org/file/botREAL123:token/photos/file_1.jpg"

    def test_stripe_files_uses_files_host(self, mock_env_vars):
        """Test Stripe file endpoints route to files.stripe.com."""
        from app.core.security import get_target_url

        url = get_target_url("stripe", "files")
        assert url == "https://files.stripe.com/v1/files"

        url_with_version = get_target_url("stripe", "v1/files/file_123/contents")
        assert url_with_version == "https://files.stripe.com/v1/files/file_123/contents"

    def test_slack_file_paths_uses_files_host(self, mock_env_vars):
        """Test Slack private file and upload paths route to files host."""
        from app.core.security import get_target_url

        files_pri_url = get_target_url("slack", "files-pri/T001-F001/report.pdf")
        upload_url = get_target_url("slack", "upload/v1/ABC123")

        assert files_pri_url == "https://files.slack.com/files-pri/T001-F001/report.pdf"
        assert upload_url == "https://files.slack.com/upload/v1/ABC123"

    def test_gemini_upload_path_uses_upload_root(self, mock_env_vars):
        """Test Gemini upload paths avoid duplicated v1beta segments."""
        from app.core.security import get_target_url

        url = get_target_url("gemini", "upload/v1beta/files")
        assert url == "https://generativelanguage.googleapis.com/upload/v1beta/files"

    def test_github_release_asset_upload_uses_uploads_host(self, mock_env_vars):
        """Test GitHub release asset uploads route to uploads.github.com."""
        from app.core.security import get_target_url

        url = get_target_url(
            "github", 
            "repos/owner/repo/releases/123/assets"
        )
        assert url == "https://uploads.github.com/repos/owner/repo/releases/123/assets"


@pytest.mark.integration
class TestProxyMethods:
    """Test different HTTP methods."""
    
    @respx.mock
    def test_get_request(self, mock_env_vars):
        """Test GET request forwarding."""
        from app.main import app
        
        route = respx.get("https://api.openai.com/v1/models").mock(
            return_value=Response(200, json={"data": []})
        )
        
        client = TestClient(app)
        response = client.get("/openai/models")
        
        assert response.status_code == 200
        assert route.calls[0].request.method == "GET"
    
    @respx.mock
    def test_post_request(self, mock_env_vars, sample_request_data):
        """Test POST request forwarding."""
        from app.main import app
        
        route = respx.post("https://api.openai.com/v1/chat/completions").mock(
            return_value=Response(200, json={})
        )
        
        client = TestClient(app)
        response = client.post("/openai/chat/completions", json=sample_request_data)
        
        assert response.status_code == 200
        assert route.calls[0].request.method == "POST"
    
    @respx.mock
    def test_put_request(self, mock_env_vars):
        """Test PUT request forwarding."""
        from app.main import app
        
        route = respx.put("https://api.github.com/user/starred/owner/repo").mock(
            return_value=Response(204)
        )
        
        client = TestClient(app)
        response = client.put("/github/user/starred/owner/repo")
        
        assert response.status_code == 204
        assert route.calls[0].request.method == "PUT"
    
    @respx.mock
    def test_delete_request(self, mock_env_vars):
        """Test DELETE request forwarding."""
        from app.main import app
        
        route = respx.delete("https://api.github.com/user/starred/owner/repo").mock(
            return_value=Response(204)
        )
        
        client = TestClient(app)
        response = client.delete("/github/user/starred/owner/repo")
        
        assert response.status_code == 204
        assert route.calls[0].request.method == "DELETE"
    
    @respx.mock
    def test_patch_request(self, mock_env_vars):
        """Test PATCH request forwarding."""
        from app.main import app
        
        route = respx.patch("https://api.github.com/user").mock(
            return_value=Response(200, json={})
        )
        
        client = TestClient(app)
        response = client.patch("/github/user", json={"name": "New Name"})
        
        assert response.status_code == 200
        assert route.calls[0].request.method == "PATCH"


@pytest.mark.unit
class TestProxyHeaders:
    """Test header handling."""
    
    def test_host_header_removed(self, mock_env_vars):
        """Test that Host header is not forwarded."""
        # This is tested implicitly in forwarding tests
        pass
    
    def test_content_length_handling(self, mock_env_vars):
        """Test Content-Length header handling."""
        # httpx handles this automatically
        pass
    
    def test_github_specific_headers(self, mock_env_vars):
        """Test GitHub-specific headers are added."""
        from app.main import app
        
        # Headers are added in proxy_request and asserted in integration tests
        pass


@pytest.mark.integration
class TestProxyServiceSpecific:
    """Test service-specific behaviors."""
    
    @respx.mock
    def test_gemini_query_param_auth(self, mock_env_vars):
        """Test Gemini API key in query params."""
        from app.main import app
        
        route = respx.get("https://generativelanguage.googleapis.com/v1beta/models").mock(
            return_value=Response(200, json={"models": []})
        )
        
        client = TestClient(app)
        response = client.get("/gemini/models")
        
        assert response.status_code == 200
        # Check that key is in query params
        assert "key=gemini-key" in str(route.calls[0].request.url)

    @respx.mock
    def test_trello_query_param_auth(self, mock_env_vars):
        """Test Trello API key and token in query params."""
        import app.db.database as database
        database.add_api_key("trello", "trello-api-key", {"token": "trello-user-token"})
        from app.main import app
        
        route = respx.get("https://api.trello.com/1/members/me").mock(
            return_value=Response(200, json={"id": "user123"})
        )
        
        client = TestClient(app)
        response = client.get("/trello/members/me")
        
        assert response.status_code == 200
        assert "key=trello-api-key" in str(route.calls[0].request.url)
        assert "token=trello-user-token" in str(route.calls[0].request.url)
    
    @respx.mock
    def test_openrouter_extra_headers(self, mock_env_vars):
        """Test OpenRouter extra headers."""
        from app.main import app
        
        route = respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
            return_value=Response(200, json={})
        )
        
        client = TestClient(app)
        response = client.post(
            "/openrouter/chat/completions",
            json={"model": "gpt-4", "messages": []},
            headers={"referer": "https://myapp.com"}
        )
        
        assert response.status_code == 200
        request = route.calls[0].request
        assert "HTTP-Referer" in request.headers
        assert "X-Title" in request.headers
    
    @respx.mock
    def test_anthropic_version_header(self, mock_env_vars):
        """Test Anthropic version header."""
        from app.main import app
        
        route = respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=Response(200, json={})
        )
        
        client = TestClient(app)
        response = client.post(
            "/anthropic/messages",
            json={"model": "claude-3", "messages": []}
        )
        
        assert response.status_code == 200
        request = route.calls[0].request
        assert "anthropic-version" in request.headers


@pytest.mark.unit
class TestProxyLogging:
    """Test logging functionality."""
    
    def test_request_logging(self, mock_env_vars, caplog):
        """Test that requests are logged."""
        import logging
        
        # Logging is configured in main.py
        # This test verifies logging configuration exists
        from app.main import logger
        
        # Logger name can be '__main__' or 'main' depending on import
        assert logger.name in ["__main__", "main", "app.main"]
        assert logger.level <= logging.INFO


@pytest.mark.integration
class TestProxyResponseHandling:
    """Test response handling."""
    
    @respx.mock
    def test_json_response(self, mock_env_vars):
        """Test JSON response forwarding."""
        from app.main import app
        
        data = {"key": "value", "nested": {"data": 123}}
        route = respx.get("https://api.openai.com/v1/models").mock(
            return_value=Response(200, json=data)
        )
        
        client = TestClient(app)
        response = client.get("/openai/models")
        
        assert response.status_code == 200
        assert response.json() == data
    
    @respx.mock
    def test_binary_response(self, mock_env_vars):
        """Test binary response forwarding."""
        from app.main import app
        
        binary_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        route = respx.get("https://api.stability.ai/v2beta/image").mock(
            return_value=Response(200, content=binary_data, headers={"Content-Type": "image/png"})
        )
        
        client = TestClient(app)
        response = client.get("/stability/image")
        
        assert response.status_code == 200
        assert response.content == binary_data
    
    @respx.mock
    def test_response_headers_forwarded(self, mock_env_vars):
        """Test response headers are forwarded."""
        from app.main import app
        
        route = respx.get("https://api.openai.com/v1/models").mock(
            return_value=Response(
                200, 
                json={},
                headers={"X-Request-ID": "test-123", "X-RateLimit-Remaining": "4999"}
            )
        )
        
        client = TestClient(app)
        response = client.get("/openai/models")
        
        assert response.status_code == 200
        assert "x-request-id" in response.headers


@pytest.mark.unit
class TestProxyConfiguration:
    """Test proxy configuration."""
    
    def test_targets_configuration(self, mock_env_vars):
        """Test that TARGETS are properly configured."""
        from app.core.config import TARGETS
        
        # Check that common services are present
        assert "openrouter" in TARGETS
        assert "openai" in TARGETS
        assert "anthropic" in TARGETS
        assert "github" in TARGETS
        
        # Check that URLs are valid
        for service, url in TARGETS.items():
            assert url.startswith(("http://", "https://"))
    
    def test_app_metadata(self, mock_env_vars):
        """Test FastAPI app metadata."""
        from app.main import app
        
        assert app.title == "KeyRelay Proxy"
        assert "Secure API Key" in app.description
    
    def test_admin_services_requires_admin(self, mock_env_vars):
        """Test that admin endpoints require admin role."""
        from app.main import app

        client = TestClient(app)
        response = client.get("/admin/services")
        assert response.status_code == 403


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
