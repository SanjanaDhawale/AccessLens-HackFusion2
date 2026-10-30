
import pytest

from security_engine.endpoint_discovery import discover_endpoints
from security_engine.models import (
    AuthorizationContext,
    ScanInput,
)
from security_engine.scope_validator import ScopeValidationError


@pytest.fixture
def scan_input():
    return ScanInput(
        scan_id="discovery-test",
        target_url="http://localhost:8888",
        authorized_hosts=["localhost"],
        authorized_ips=["127.0.0.1", "::1"],
        allow_private_targets=True,
        allowed_paths=["/"],
        endpoints=[],
        scan_profile="OWASP_API_TOP_10_SAFE",
        authorization_context=AuthorizationContext(
            authorization_confirmed=True,
            credentials_available=False,
        ),
    )


@pytest.fixture
def routes():
    return {
        "LOGIN": {
            "service": "identity",
            "path": "api/auth/login",
        },
        "GET_USER": {
            "service": "identity",
            "path": "api/v2/user/dashboard",
        },
        "GET_PRODUCTS": {
            "service": "workshop",
            "path": "api/shop/products",
        },
    }


@pytest.fixture
def methods():
    return {
        "LOGIN": "POST",
        "GET_USER": "GET",
        "GET_PRODUCTS": "GET",
    }


def test_discovers_valid_endpoints(
    scan_input, routes, methods
):
    endpoints = discover_endpoints(
        scan_input, routes, methods
    )

    assert len(endpoints) == 3

    discovered = {
        (endpoint.method, endpoint.path)
        for endpoint in endpoints
    }

    assert ("POST", "/identity/api/auth/login") in discovered
    assert (
        "GET",
        "/identity/api/v2/user/dashboard",
    ) in discovered
    assert (
        "GET",
        "/workshop/api/shop/products",
    ) in discovered


def test_skips_routes_without_verified_methods(
    scan_input, routes
):
    methods = {
        "LOGIN": "POST",
    }

    endpoints = discover_endpoints(
        scan_input, routes, methods
    )

    assert len(endpoints) == 1
    assert endpoints[0].path == "/identity/api/auth/login"


def test_rejects_unsupported_service(
    scan_input, methods
):
    routes = {
        "INVALID": {
            "service": "unknown",
            "path": "api/test",
        }
    }

    with pytest.raises(ValueError):
        discover_endpoints(
            scan_input, routes, methods
        )


def test_rejects_invalid_http_method(
    scan_input, routes
):
    methods = {
        "LOGIN": "TRACE",
    }

    with pytest.raises(ValueError):
        discover_endpoints(
            scan_input, routes, methods
        )


def test_removes_duplicate_endpoints(
    scan_input
):
    routes = {
        "LOGIN": {
            "service": "identity",
            "path": "api/auth/login",
        },
        "LOGIN_DUPLICATE": {
            "service": "identity",
            "path": "api/auth/login",
        },
    }

    methods = {
        "LOGIN": "POST",
        "LOGIN_DUPLICATE": "POST",
    }

    endpoints = discover_endpoints(
        scan_input, routes, methods
    )

    assert len(endpoints) == 1


def test_rejects_missing_authorization(
    scan_input, routes, methods
):
    scan_input.authorization_context.authorization_confirmed = False

    with pytest.raises(ValueError):
        discover_endpoints(
            scan_input, routes, methods
        )


def test_rejects_out_of_scope_endpoints(
    scan_input, routes, methods, monkeypatch
):
    def reject_scope(_):
        raise ScopeValidationError(
            "Endpoint is outside authorized scope."
        )

    monkeypatch.setattr(
        "security_engine.endpoint_discovery.validate_scan_scope",
        reject_scope,
    )

    with pytest.raises(ScopeValidationError):
        discover_endpoints(
            scan_input, routes, methods
        )
