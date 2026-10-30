import re
from typing import Any


SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
}

SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "secret",
    "client_secret",
    "access_token",
    "refresh_token",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
}


REDACTED_VALUE = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())

    return (
        normalized in {
            re.sub(r"[^a-z0-9]", "", item)
            for item in SENSITIVE_HEADERS | SENSITIVE_FIELDS
        }
        or normalized.endswith("token")
        or normalized.endswith("secret")
        or normalized.endswith("apikey")
    )


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}

        for key, item in value.items():
            if is_sensitive_key(str(key)):
                redacted[key] = REDACTED_VALUE
            else:
                redacted[key] = redact_value(item)

        return redacted

    if isinstance(value, list):
        return [redact_value(item) for item in value]

    if isinstance(value, str):
        # Redact common credential formats in free-text values.
        patterns = [
            r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+",
            r"(?i)(basic\s+)[A-Za-z0-9+/=]+",
            r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,;]+",
            r"(?i)(password\s*[:=]\s*)[^\s,;]+",
            r"(?i)(access[_-]?token\s*[:=]\s*)[^\s,;]+",
        ]

        for pattern in patterns:
            value = re.sub(
                pattern,
                lambda match: match.group(1) + REDACTED_VALUE,
                value,
            )

        return value

    return value


def redact_evidence(request: dict, response: dict) -> tuple[dict, dict]:
    """
    Redact sensitive information before evidence is stored.
    """

    safe_request = redact_value(request)
    safe_response = redact_value(response)

    return safe_request, safe_response