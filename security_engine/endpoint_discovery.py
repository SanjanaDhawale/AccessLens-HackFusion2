
"""Safe endpoint inventory construction from authorized frontend routes.

This module does not send HTTP requests or actively probe endpoints.
It converts routes and HTTP methods verified by the operator into
validated Endpoint models.
"""

from collections.abc import Mapping

from security_engine.models import (
    Endpoint,
    EndpointSource,
    ScanInput,
)
from security_engine.scope_validator import validate_scan_scope


SERVICE_PREFIXES = {
    "identity": "/identity/",
    "workshop": "/workshop/",
    "chatbot": "/chatbot/",
    "community": "/community/",
}

ALLOWED_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


def discover_endpoints(
    scan_input: ScanInput,
    route_definitions: Mapping[str, Mapping[str, str]],
    method_map: Mapping[str, str],
) -> list[Endpoint]:
    """Build and validate endpoints from inspected frontend routes.

    Args:
        scan_input:
            Existing, explicitly authorized scan configuration.

        route_definitions:
            Mapping of route names to service and relative path.

            Example:
            {
                "LOGIN": {
                    "service": "identity",
                    "path": "api/auth/login",
                }
            }

        method_map:
            Mapping of route names to verified HTTP methods.

            Example:
            {
                "LOGIN": "POST",
                "GET_USER": "GET",
            }

    Returns:
        A list of validated Endpoint objects.

    Raises:
        ValueError:
            If route definitions or methods are invalid.

        ScopeValidationError:
            If the resulting endpoints are outside authorized scope.
    """

    if not scan_input.authorization_context.authorization_confirmed:
        raise ValueError(
            "Explicit authorization confirmation is required."
        )

    if not route_definitions:
        raise ValueError("No route definitions were provided.")

    endpoints = []
    seen = set()

    for route_name, definition in route_definitions.items():

        if not isinstance(route_name, str) or not route_name.strip():
            raise ValueError("Invalid route name.")

        if not isinstance(definition, Mapping):
            raise ValueError(
                f"Invalid route definition: {route_name}"
            )

        service = definition.get("service")
        relative_path = definition.get("path")

        if service not in SERVICE_PREFIXES:
            raise ValueError(
                f"Unsupported service for route {route_name}."
            )

        if not isinstance(relative_path, str) or not relative_path:
            raise ValueError(
                f"Missing path for route {route_name}."
            )

        # Only include routes whose HTTP methods have been verified.
        method = method_map.get(route_name)

        if method is None:
            continue

        if not isinstance(method, str):
            raise ValueError(
                f"Invalid HTTP method for route {route_name}."
            )

        method = method.upper()

        if method not in ALLOWED_METHODS:
            raise ValueError(
                f"Unsupported HTTP method for route {route_name}."
            )

        # Frontend route definitions must be relative paths.
        if (
            relative_path.startswith("/")
            or "?" in relative_path
            or "#" in relative_path
            or "\\" in relative_path
            or "://" in relative_path
        ):
            raise ValueError(
                f"Invalid relative route path: {route_name}."
            )

        # Combine the service prefix with its API route.
        endpoint_path = (
            SERVICE_PREFIXES[service] + relative_path
        )

        if not endpoint_path.startswith("/"):
            raise ValueError("Endpoint path must be absolute.")

        endpoint_key = (endpoint_path, method)

        if endpoint_key in seen:
            continue

        endpoint = Endpoint(
            path=endpoint_path,
            method=method,
            operation_id=route_name,
            source=EndpointSource.AUTHORIZED_DISCOVERY,
        )

        endpoints.append(endpoint)
        seen.add(endpoint_key)

    if not endpoints:
        raise ValueError(
            "No endpoints with verified HTTP methods were found."
        )

    # Validate the complete discovered inventory against the
    # existing authorization, hostname, IP and path restrictions.
    candidate_scan = scan_input.model_copy(
        update={"endpoints": endpoints}
    )

    validate_scan_scope(candidate_scan)

    return endpoints
