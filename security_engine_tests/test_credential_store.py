
import pytest

from security_engine.credential_store import (
    CredentialResolutionError,
    resolve_bearer_token,
)


def test_resolves_user_a_token(monkeypatch):
    monkeypatch.setenv("CRAPI_USER_A_TOKEN", "test.jwt.token")

    result = resolve_bearer_token("CRAPI_USER_A")

    assert result == "test.jwt.token"


def test_resolves_user_b_token(monkeypatch):
    monkeypatch.setenv("CRAPI_USER_B_TOKEN", "another.jwt.token")

    result = resolve_bearer_token("CRAPI_USER_B")

    assert result == "another.jwt.token"


def test_removes_bearer_prefix(monkeypatch):
    monkeypatch.setenv(
        "CRAPI_USER_A_TOKEN",
        "Bearer test.jwt.token",
    )

    result = resolve_bearer_token("CRAPI_USER_A")

    assert result == "test.jwt.token"


def test_rejects_missing_credential(monkeypatch):
    monkeypatch.delenv("CRAPI_USER_A_TOKEN", raising=False)

    with pytest.raises(CredentialResolutionError):
        resolve_bearer_token("CRAPI_USER_A")


def test_rejects_unsupported_reference():
    with pytest.raises(CredentialResolutionError):
        resolve_bearer_token("UNKNOWN_USER")


def test_rejects_invalid_token_characters(monkeypatch):
    monkeypatch.setenv(
        "CRAPI_USER_A_TOKEN",
        "invalid token with spaces",
    )

    with pytest.raises(CredentialResolutionError):
        resolve_bearer_token("CRAPI_USER_A")
