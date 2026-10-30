
from __future__ import annotations

import os
import re


# Only explicitly approved credential references are supported.
CREDENTIAL_ENV_MAP = {
    "CRAPI_USER_A": "CRAPI_USER_A_TOKEN",
    "CRAPI_USER_B": "CRAPI_USER_B_TOKEN",
}


class CredentialResolutionError(ValueError):
    """Raised when a required credential cannot be resolved."""


def resolve_bearer_token(credential_ref: str) -> str:
    """
    Resolve an approved credential reference from environment variables.

    The returned token is intended for in-memory HTTP authentication only.
    Never log, print, persist or include it in evidence.
    """

    if credential_ref not in CREDENTIAL_ENV_MAP:
        raise CredentialResolutionError(
            "Unsupported credential reference."
        )

    env_name = CREDENTIAL_ENV_MAP[credential_ref]
    token = os.environ.get(env_name)

    if not token:
        raise CredentialResolutionError(
            f"Credential '{credential_ref}' is not configured."
        )

    token = token.strip()

    # Accept either a raw token or a Bearer-prefixed value.
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    if not token:
        raise CredentialResolutionError(
            "Configured credential is empty."
        )

    if len(token) > 8192:
        raise CredentialResolutionError(
            "Configured credential exceeds the permitted size."
        )

    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token):
        raise CredentialResolutionError(
            "Configured credential contains invalid characters."
        )

    return token
