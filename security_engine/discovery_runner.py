
"""Integration wrapper for endpoint discovery and security scanning."""

from collections.abc import Mapping

from security_engine.models import ScanInput
from security_engine.endpoint_discovery import discover_endpoints
from security_engine.engine import run_security_scan


def run_discovered_security_scan(
    scan_input: dict,
    route_definitions: Mapping[str, Mapping[str, str]],
    method_map: Mapping[str, str],
) -> dict:
    """Discover authorized endpoints, then run the existing scan engine.

    Route definitions and HTTP methods must be verified by the operator.
    This function does not parse JavaScript or actively discover routes.
    """

    if not isinstance(scan_input, dict):
        raise TypeError("scan_input must be a dictionary.")

    validated_input = ScanInput.model_validate(scan_input)

    endpoints = discover_endpoints(
        scan_input=validated_input,
        route_definitions=route_definitions,
        method_map=method_map,
    )

    enriched_input = validated_input.model_dump(mode="json")
    enriched_input["endpoints"] = [
        endpoint.model_dump(mode="json")
        for endpoint in endpoints
    ]

    return run_security_scan(enriched_input)
