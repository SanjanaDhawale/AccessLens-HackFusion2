
import pytest

from security_engine.models import ScanInput
from security_engine.scope_validator import (
    ScopeValidationError,
    validate_scan_scope,
)


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


def test_authorized_target_is_accepted():
    scan = make_scan_input()
    validate_scan_scope(scan)


def test_unauthorized_host_is_rejected():
    scan = make_scan_input(target_url="http://example.com")

    with pytest.raises(ScopeValidationError):
        validate_scan_scope(scan)


def test_missing_authorization_is_rejected():
    scan = make_scan_input(
        authorization_context={
            "authorization_confirmed": False,
            "credentials_available": False,
        },
    )

    with pytest.raises(ScopeValidationError):
        validate_scan_scope(scan)


def test_endpoint_outside_allowed_path_is_rejected():
    scan = make_scan_input(
        endpoints=[
            {
                "path": "/admin/users",
                "method": "GET",
                "source": "USER_PROVIDED",
            }
        ],
    )

    with pytest.raises(ScopeValidationError):
        validate_scan_scope(scan)


def test_path_prefix_boundary_is_enforced():
    scan = make_scan_input(
        endpoints=[
            {
                "path": "/identity/api-evil/users",
                "method": "GET",
                "source": "USER_PROVIDED",
            }
        ],
    )

    with pytest.raises(ScopeValidationError):
        validate_scan_scope(scan)


def test_loopback_target_is_blocked_without_explicit_opt_in():
    scan = make_scan_input(
        target_url="http://127.0.0.1:8888",
        authorized_hosts=["127.0.0.1"],
        allow_private_targets=False,
        authorized_ips=[],
    )
    with pytest.raises(ScopeValidationError, match="blocked by default"):
        validate_scan_scope(scan)


def test_private_target_requires_exact_authorized_ip():
    scan = make_scan_input(
        target_url="http://127.0.0.1:8888",
        authorized_hosts=["127.0.0.1"],
        allow_private_targets=True,
        authorized_ips=["127.0.0.2"],
    )
    with pytest.raises(ScopeValidationError, match="authorized_ips"):
        validate_scan_scope(scan)


def test_dns_resolution_failure_is_rejected(monkeypatch):
    import socket

    scan = make_scan_input(
        target_url="https://api.example.test",
        authorized_hosts=["api.example.test"],
        allow_private_targets=False,
        authorized_ips=[],
    )

    def fail_dns(*args, **kwargs):
        raise socket.gaierror("not found")

    monkeypatch.setattr("security_engine.scope_validator.socket.getaddrinfo", fail_dns)
    with pytest.raises(ScopeValidationError, match="could not be resolved"):
        validate_scan_scope(scan)


def test_public_dns_address_is_accepted(monkeypatch):
    scan = make_scan_input(
        target_url="https://api.example.test",
        authorized_hosts=["api.example.test"],
        allow_private_targets=False,
        authorized_ips=[],
    )
    monkeypatch.setattr(
        "security_engine.scope_validator.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 443))],
    )
    validate_scan_scope(scan)
