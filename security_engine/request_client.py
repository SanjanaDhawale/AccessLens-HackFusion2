
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from security_engine.models import ScanInput
from security_engine.scope_validator import (
    ScopeValidationError,
    validate_scan_scope,
    _validate_path,
    resolve_target_addresses,
)
from security_engine.redaction import redact_headers, redact_text


@dataclass
class SafeResponse:
    """A limited and sanitized HTTP response."""

    status_code: int
    headers: dict[str, str]
    body_excerpt: str
    url: str


class SafeRequestClient:
    """HTTP client restricted to explicitly authorized API scope."""

    ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}

    BLOCKED_HEADERS = {
        "host",
        "connection",
        "proxy-authorization",
        "transfer-encoding",
        "content-length",
    }

    def __init__(
        self,
        scan_input: ScanInput,
        timeout: float = 5.0,
        max_response_bytes: int = 256_000,
        max_requests: int = 20,
    ) -> None:

        if timeout <= 0 or max_response_bytes <= 0 or max_requests <= 0:
            raise ValueError("Client limits must be positive.")

        # Validate authorization and scope before creating HTTPX.
        validate_scan_scope(scan_input)

        self.scan_input = scan_input
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_requests = max_requests
        self.request_count = 0
        self._initial_resolved_addresses = resolve_target_addresses(scan_input)

        self.base_url = scan_input.target_url.rstrip("/") + "/"

        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "AccessLens-SafeScanner/1.0"
            },
        )

    def _validate_request_url(self, url: str) -> None:
        """Validate the complete URL against the authorized scope."""

        try:
            requested = urlsplit(url)
            base = urlsplit(self.scan_input.target_url)

            requested_port = requested.port
            base_port = base.port

        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid request URL or port."
            ) from exc

        # Re-resolve before each request to detect DNS changes/rebinding
        # between scan validation and request execution.
        current_addresses = resolve_target_addresses(self.scan_input)
        if current_addresses != self._initial_resolved_addresses:
            raise ScopeValidationError(
                "Target DNS resolution changed during the scan."
            )

        if requested.scheme != base.scheme:
            raise ScopeValidationError(
                "Request scheme differs from target."
            )

        if requested.scheme not in {"http", "https"}:
            raise ScopeValidationError(
                "Unsupported request scheme."
            )

        if requested.username is not None or requested.password is not None:
            raise ScopeValidationError(
                "URL credentials are not allowed."
            )

        if requested.hostname is None or base.hostname is None:
            raise ScopeValidationError(
                "Request hostname is missing."
            )

        if requested.hostname.lower().rstrip(".") != (
            base.hostname.lower().rstrip(".")
        ):
            raise ScopeValidationError(
                "Request host differs from target."
            )

        requested_effective_port = (
            requested_port
            if requested_port is not None
            else (443 if requested.scheme == "https" else 80)
        )

        base_effective_port = (
            base_port
            if base_port is not None
            else (443 if base.scheme == "https" else 80)
        )

        if not (1 <= requested_effective_port <= 65535):
            raise ScopeValidationError(
                "Request port is invalid."
            )

        if requested_effective_port != base_effective_port:
            raise ScopeValidationError(
                "Request port differs from target."
            )

        if requested.fragment:
            raise ScopeValidationError(
                "URL fragments are not allowed."
            )

        # Query parameters are allowed for API requests.
        # Path validation includes repeated URL decoding.
        decoded_path = _validate_path(
            requested.path or "/",
            "HTTP request path",
        )

        allowed = False

        for prefix in self.scan_input.allowed_paths:
            prefix = prefix.rstrip("/") or "/"

            if (
                decoded_path == prefix
                or prefix == "/"
                or decoded_path.startswith(prefix + "/")
            ):
                allowed = True
                break

        if not allowed:
            raise ScopeValidationError(
                "Request path is outside authorized scope."
            )

    def _validate_headers(
        self,
        headers: dict[str, str] | None,
    ) -> dict[str, str]:

        safe_headers = {}

        for name, value in (headers or {}).items():

            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError(
                    "HTTP header names and values must be strings."
                )

            if name.lower() in self.BLOCKED_HEADERS:
                raise ValueError(
                    f"Header '{name}' cannot be overridden."
                )

            if (
                not name
                or any(
                    ord(char) < 33 or ord(char) > 126
                    for char in name
                )
                or any(
                    ord(char) < 32 or ord(char) == 127
                    for char in value
                )
            ):
                raise ValueError("Invalid HTTP header.")

            safe_headers[name] = value

        return safe_headers

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
    ) -> SafeResponse:

        if not isinstance(method, str):
            raise ValueError("HTTP method must be a string.")

        method = method.upper()

        if method not in self.ALLOWED_METHODS:
            raise ValueError(
                "Only GET, HEAD and OPTIONS are permitted."
            )

        if self.request_count >= self.max_requests:
            raise RuntimeError(
                "Maximum request count reached."
            )

        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
        ):
            raise ScopeValidationError(
                "Request path must be an absolute API path."
            )

        parsed_path = urlsplit(path)

        if (
            parsed_path.scheme
            or parsed_path.netloc
            or parsed_path.fragment
        ):
            raise ScopeValidationError(
                "Request path contains unsupported URL components."
            )

        # Validate before URL construction to reject traversal,
        # encoded separators and malformed encoding.
        _validate_path(
            parsed_path.path or "/",
            "HTTP request path",
        )

        if any(
            ord(char) < 32 or ord(char) == 127
            for char in path
        ):
            raise ScopeValidationError(
                "Invalid characters in request path."
            )

        url = urljoin(
            self.base_url,
            path.lstrip("/")
        )

        self._validate_request_url(url)

        request_headers = self._validate_headers(headers)

        # Count only requests that pass all local validation.
        self.request_count += 1

        try:
            with self._client.stream(
                method,
                url,
                headers=request_headers,
                follow_redirects=False,
            ) as response:

                body = bytearray()

                for chunk in response.iter_bytes():
                    remaining = self.max_response_bytes - len(body)

                    if remaining <= 0:
                        break

                    body.extend(chunk[:remaining])

                    if len(body) >= self.max_response_bytes:
                        break

                response_headers = redact_headers(
                    dict(response.headers)
                )

                body_excerpt = redact_text(
                    body.decode("utf-8", errors="replace")
                )

                return SafeResponse(
                    status_code=response.status_code,
                    headers=response_headers,
                    body_excerpt=body_excerpt,
                    url=str(response.url),
                )

        except httpx.TimeoutException as exc:
            raise RuntimeError(
                "HTTP request timed out."
            ) from exc

        except httpx.HTTPError as exc:
            raise RuntimeError(
                "HTTP request failed."
            ) from exc

    def close(self) -> None:
        """Close the HTTPX client."""

        self._client.close()

    def __enter__(self) -> "SafeRequestClient":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
