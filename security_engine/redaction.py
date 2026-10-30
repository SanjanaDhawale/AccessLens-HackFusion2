
from __future__ import annotations

import re


REDACTED = "[REDACTED]"

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
}

SENSITIVE_VALUE_PATTERNS = [
    # Redact the complete Bearer token first.
    re.compile(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"
    ),

    # Redact sensitive JSON and key-value fields.
    re.compile(
        r'(?i)("?(?:password|passwd|secret|token|access_token|'
        r'refresh_token|api_key|apikey|client_secret|authorization|'
        r'cookie|pin|vin)"?\s*[:=]\s*)'
        r'("[^"]*"|\'[^\']*\'|[^,\s}&]+)'
    ),
]


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive HTTP headers."""

    safe_headers = {}

    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADER_NAMES:
            safe_headers[name] = REDACTED
        else:
            safe_headers[name] = str(value)

    return safe_headers


def redact_text(text: str) -> str:
    """Redact sensitive fields and bearer tokens from text."""

    if not isinstance(text, str):
        return ""

    safe_text = text

    for pattern in SENSITIVE_VALUE_PATTERNS:
        if pattern.groups:
            safe_text = pattern.sub(
                lambda match: match.group(1) + f'"{REDACTED}"',
                safe_text,
            )
        else:
            safe_text = pattern.sub(REDACTED, safe_text)

    return safe_text
