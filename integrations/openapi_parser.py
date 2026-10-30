from typing import Any
import yaml


SUPPORTED_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
}


class OpenAPIParseError(ValueError):
    """Raised when an OpenAPI specification is invalid."""


def parse_openapi(content: str) -> dict[str, Any]:
    """Parse an OpenAPI JSON or YAML document."""

    try:
        specification = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise OpenAPIParseError("Invalid JSON/YAML specification.") from exc

    if not isinstance(specification, dict):
        raise OpenAPIParseError("Specification must be a JSON/YAML object.")

    version = specification.get("openapi")

    if not isinstance(version, str) or not version.startswith("3."):
        raise OpenAPIParseError(
            "Only OpenAPI 3.x specifications are currently supported."
        )

    paths = specification.get("paths")

    if not isinstance(paths, dict):
        raise OpenAPIParseError("Specification must contain a paths object.")

    endpoints = []

    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue

        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            method = method.upper()

            if method not in SUPPORTED_METHODS:
                continue

            if not isinstance(operation, dict):
                continue

            endpoints.append({
                "path": path,
                "method": method,
                "operation_id": operation.get("operationId"),
                "summary": operation.get("summary"),
                "tags": operation.get("tags", []),
                "source": "OPENAPI"
            })

    return {
        "openapi_version": version,
        "title": specification.get("info", {}).get("title", "Untitled API"),
        "endpoints": endpoints,
        "total_endpoints": len(endpoints)
    }