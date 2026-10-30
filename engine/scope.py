"""Every outbound request must pass this target scope guard."""
from urllib.parse import urlparse

class ScopeViolation(ValueError):
    pass

def validate_target_url(url: str, allowed_hosts: set[str]) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ScopeViolation("Only HTTP(S) targets are allowed")
    if not parsed.hostname or parsed.hostname.lower() not in {h.lower() for h in allowed_hosts}:
        raise ScopeViolation("Target host is outside explicitly allowed scope")
    if parsed.username or parsed.password:
        raise ScopeViolation("Credentials must not be embedded in target URLs")
    return url
