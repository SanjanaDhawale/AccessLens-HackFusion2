
import ipaddress
import re
import socket
from urllib.parse import unquote, urlsplit

from security_engine.models import ScanInput


class ScopeValidationError(ValueError):
    """Raised when a scan request is outside the authorized scope."""


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _path_is_allowed(path: str, allowed_paths: list[str]) -> bool:
    """Check exact path or directory-prefix boundary."""

    for prefix in allowed_paths:
        prefix = prefix.rstrip("/") or "/"

        if path == prefix:
            return True

        if prefix == "/":
            return True

        if path.startswith(prefix + "/"):
            return True

    return False


def _validate_path(path: str, description: str) -> str:
    """
    Decode and validate paths against traversal, encoded separators,
    malformed encoding and ambiguous URL components.
    """

    raw_path = path or "/"

    if not raw_path.startswith("/") or raw_path.startswith("//"):
        raise ScopeValidationError(
            f"{description} must be an absolute path."
        )

    if "?" in raw_path or "#" in raw_path:
        raise ScopeValidationError(
            f"{description} must not contain a query or fragment."
        )

    decoded_path = raw_path

    # Repeated decoding detects double-encoded traversal and separators.
    for _ in range(8):
        if re.search(r"%(?![0-9a-fA-F]{2})", decoded_path):
            raise ScopeValidationError(
                f"{description} contains malformed URL encoding."
            )

        if re.search(r"%(?:2f|5c)", decoded_path, re.IGNORECASE):
            raise ScopeValidationError(
                f"{description} contains an encoded path separator."
            )

        next_path = unquote(decoded_path)

        if next_path == decoded_path:
            break

        decoded_path = next_path
    else:
        raise ScopeValidationError(
            f"{description} contains excessive URL encoding."
        )

    if "\\" in decoded_path:
        raise ScopeValidationError(
            f"{description} contains an invalid separator."
        )

    if "?" in decoded_path or "#" in decoded_path:
        raise ScopeValidationError(
            f"{description} contains an encoded query or fragment."
        )

    if any(ord(char) < 32 or ord(char) == 127 for char in decoded_path):
        raise ScopeValidationError(
            f"{description} contains control characters."
        )

    if decoded_path.startswith("//"):
        raise ScopeValidationError(
            f"{description} contains an invalid leading separator."
        )

    if any(part in {".", ".."} for part in decoded_path.split("/")):
        raise ScopeValidationError(
            f"{description} contains path traversal."
        )

    return decoded_path



def resolve_target_addresses(scan_input: ScanInput) -> set[str]:
    """Resolve the authorized hostname and enforce address policy.

    Private, loopback, link-local, multicast, reserved and unspecified
    addresses are denied by default. Lab/private targets require an explicit
    opt-in and an exact authorized_ips allowlist.
    """
    parsed = urlsplit(scan_input.target_url)
    hostname = parsed.hostname
    if not hostname:
        raise ScopeValidationError("Target hostname is missing.")

    try:
        literal = ipaddress.ip_address(hostname)
        addresses = {str(literal)}
    except ValueError:
        try:
            records = socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
            addresses = {str(ipaddress.ip_address(item[4][0])) for item in records}
        except (OSError, ValueError):
            raise ScopeValidationError("Target hostname could not be resolved.") from None

    if not addresses:
        raise ScopeValidationError("Target hostname resolved to no addresses.")

    parsed_addresses = {ipaddress.ip_address(value) for value in addresses}
    non_public = {str(value) for value in parsed_addresses if not value.is_global}

    if non_public:
        if not scan_input.allow_private_targets:
            raise ScopeValidationError(
                "Private, loopback, link-local or reserved target addresses are blocked by default."
            )
        authorized_ips = set(scan_input.authorized_ips)
        if not authorized_ips or not addresses.issubset(authorized_ips):
            raise ScopeValidationError(
                "Private targets require an exact authorized_ips allowlist covering every resolved address."
            )

    if scan_input.authorized_ips and not addresses.issubset(set(scan_input.authorized_ips)):
        raise ScopeValidationError(
            "Resolved target addresses are outside authorized_ips."
        )

    return addresses


def validate_scan_scope(scan_input: ScanInput) -> None:
    """
    Validate authorization, target host, URL, endpoint paths
    and optional BOLA object paths.

    This function performs no network requests.
    """

    # 1. Explicit authorization check
    if not scan_input.authorization_context.authorization_confirmed:
        raise ScopeValidationError(
            "Explicit authorization confirmation is required."
        )

    # 2. Parse and validate target URL
    try:
        parsed = urlsplit(scan_input.target_url)
        port = parsed.port
    except ValueError as exc:
        raise ScopeValidationError(
            "Invalid target URL or port."
        ) from exc

    if parsed.scheme not in {"http", "https"}:
        raise ScopeValidationError(
            "Only HTTP and HTTPS targets are allowed."
        )

    if not parsed.hostname:
        raise ScopeValidationError(
            "Target hostname is missing."
        )

    # 3. Reject embedded credentials
    if parsed.username is not None or parsed.password is not None:
        raise ScopeValidationError(
            "URL credentials are not allowed."
        )

    # 4. Reject query parameters and fragments in base URL
    if parsed.query or parsed.fragment:
        raise ScopeValidationError(
            "Target URL must not contain a query or fragment."
        )

    # 5. Validate port
    if port is not None and not (1 <= port <= 65535):
        raise ScopeValidationError(
            "Target port is invalid."
        )

    # 6. Exact hostname allowlist check
    hostname = _normalize_host(parsed.hostname)

    authorized_hosts = {
        _normalize_host(host)
        for host in scan_input.authorized_hosts
    }

    if hostname not in authorized_hosts:
        raise ScopeValidationError(
            f"Target host '{hostname}' is not authorized."
        )

    # Resolve DNS and enforce public/private address policy.
    resolve_target_addresses(scan_input)

    # 7. Validate target base path
    decoded_path = _validate_path(
        parsed.path or "/",
        "Target base path"
    )

    if decoded_path != "/" and not _path_is_allowed(
        decoded_path,
        scan_input.allowed_paths
    ):
        raise ScopeValidationError(
            "Target base path is outside the authorized path scope."
        )

    # 8. Validate every requested endpoint
    for endpoint in scan_input.endpoints:
        endpoint_path = _validate_path(
            endpoint.path,
            "Endpoint path"
        )

        if not _path_is_allowed(
            endpoint_path,
            scan_input.allowed_paths
        ):
            raise ScopeValidationError(
                f"Endpoint path '{endpoint.path}' "
                "is outside the authorized scope."
            )

    # 9. Validate optional BOLA object reference path
    if scan_input.bola_test is not None:
        object_path = _validate_path(
            scan_input.bola_test.object_reference.read_path,
            "BOLA object reference path"
        )

        if not _path_is_allowed(
            object_path,
            scan_input.allowed_paths
        ):
            raise ScopeValidationError(
                "BOLA object reference path is outside "
                "the authorized path scope."
            )
