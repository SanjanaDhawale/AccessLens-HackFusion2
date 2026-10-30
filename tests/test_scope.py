import pytest
from engine.scope import ScopeViolation, validate_target_url

def test_allows_explicit_local_host():
    assert validate_target_url("http://127.0.0.1:8001/health", {"127.0.0.1"}).startswith("http://")

def test_rejects_host_outside_scope():
    with pytest.raises(ScopeViolation):
        validate_target_url("https://example.com", {"127.0.0.1"})

def test_rejects_non_http_scheme():
    with pytest.raises(ScopeViolation):
        validate_target_url("file:///etc/passwd", {"127.0.0.1"})
