
import httpx
import pytest

from unittest.mock import patch

from security_engine.models import ScanInput
from security_engine.request_client import SafeRequestClient
from security_engine.scope_validator import ScopeValidationError


def make_scan_input(**overrides):
    data = {
        "scan_id": "test-001",
        "target_url": "http://localhost:8888",
        "authorized_hosts": ["localhost"],
        "allowed_paths": ["/identity/api/"],
        "endpoints": [],
        "scan_profile": "OWASP_API_TOP_10_SAFE",
        "authorization_context": {
            "authorization_confirmed": True,
            "credentials_available": False,
        },
        "allow_private_targets": True,
        "authorized_ips": ["127.0.0.1", "::1"],
    }

    data.update(overrides)
    return ScanInput.model_validate(data)


def test_client_rejects_missing_authorization():
    scan = make_scan_input(
        authorization_context={
            "authorization_confirmed": False,
            "credentials_available": False,
        }
    )

    with pytest.raises(ScopeValidationError):
        SafeRequestClient(scan)


def test_client_rejects_unsafe_http_method():
    scan = make_scan_input()

    with SafeRequestClient(scan) as client:
        with pytest.raises(ValueError):
            client.request("DELETE", "/identity/api/test")


def test_client_rejects_out_of_scope_path():
    scan = make_scan_input()

    with SafeRequestClient(scan) as client:
        with pytest.raises(ScopeValidationError):
            client.request("GET", "/admin/users")


def test_client_rejects_host_header_override():
    scan = make_scan_input()

    with SafeRequestClient(scan) as client:
        with pytest.raises(ValueError):
            client.request(
                "GET",
                "/identity/api/test",
                headers={"Host": "example.com"},
            )


def test_client_returns_mocked_response():
    scan = make_scan_input()

    mock_response = httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        json={"message": "Mock API response"},
        request=httpx.Request(
            "GET",
            "http://localhost:8888/identity/api/test",
        ),
    )

    with patch(
        "security_engine.request_client.httpx.Client.stream"
    ) as mocked_stream:

        mocked_stream.return_value.__enter__.return_value = mock_response

        with SafeRequestClient(scan) as client:
            response = client.request(
                "GET",
                "/identity/api/test",
            )

    assert response.status_code == 200
    assert "Mock API response" in response.body_excerpt

def test_client_rejects_encoded_path_traversal():
    scan = make_scan_input()

    with SafeRequestClient(scan) as client:
        with pytest.raises(ScopeValidationError):
            client.request(
                "GET",
                "/identity/api/%2e%2e/admin",
            )


def test_client_rejects_double_encoded_path_traversal():
    scan = make_scan_input()

    with SafeRequestClient(scan) as client:
        with pytest.raises(ScopeValidationError):
            client.request(
                "GET",
                "/identity/api/%252e%252e/admin",
            )


def test_client_rejects_encoded_path_separator():
    scan = make_scan_input()

    with SafeRequestClient(scan) as client:
        with pytest.raises(ScopeValidationError):
            client.request(
                "GET",
                "/identity/api/users%2f..%2fadmin",
            )


def test_client_rejects_external_absolute_url():
    scan = make_scan_input()

    with SafeRequestClient(scan) as client:
        with pytest.raises(ScopeValidationError):
            client.request(
                "GET",
                "https://example.com/identity/api/test",
            )


def test_client_rejects_dns_resolution_change(monkeypatch):
    scan = make_scan_input()
    with SafeRequestClient(scan) as client:
        monkeypatch.setattr(
            "security_engine.request_client.resolve_target_addresses",
            lambda value: {"203.0.113.10"},
        )
        with pytest.raises(ScopeValidationError, match="DNS resolution changed"):
            client.request("GET", "/identity/api/test")
