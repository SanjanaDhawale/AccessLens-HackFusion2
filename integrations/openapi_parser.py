from typing import Any
from urllib.parse import urlsplit

import yaml


SUPPORTED_METHODS = {
    "GET", "POST", "PUT", "PATCH",
    "DELETE", "OPTIONS", "HEAD"
}


class OpenAPIParseError(ValueError):
    """Raised when an OpenAPI specification is invalid."""


def parse_openapi(content: str) -> dict[str, Any]:
    """Parse an OpenAPI JSON or YAML document."""

    try:
        specification = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise OpenAPIParseError(
            "Invalid JSON/YAML specification."
        ) from exc

    if not isinstance(specification, dict):
        raise OpenAPIParseError(
            "Specification must be a JSON/YAML object."
        )

    version = specification.get("openapi")

    if not isinstance(version, str) or not version.startswith("3."):
        raise OpenAPIParseError(
            "Only OpenAPI 3.x specifications are supported."
        )

    info = specification.get("info")

    if not isinstance(info, dict):
        raise OpenAPIParseError(
            "Specification must contain a valid info object."
        )

    paths = specification.get("paths")

    if not isinstance(paths, dict):
        raise OpenAPIParseError(
            "Specification must contain a paths object."
        )

    servers = specification.get("servers", [])

    if not isinstance(servers, list):
        raise OpenAPIParseError(
            "Specification servers must be a list."
        )

    server_urls = []

    for server in servers:
        if not isinstance(server, dict):
            raise OpenAPIParseError("Invalid server definition.")

        server_url = server.get("url")

        if not isinstance(server_url, str):
            raise OpenAPIParseError("Invalid server URL.")

        parsed_url = urlsplit(server_url)

        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username
            or parsed_url.password
        ):
            raise OpenAPIParseError(
                "Server URLs must be valid HTTP or HTTPS URLs."
            )

        if "{" in server_url or "}" in server_url:
            raise OpenAPIParseError(
                "Templated server URLs are not supported yet."
            )

        server_urls.append(server_url)

    endpoints = []

    for path, path_item in paths.items():

        if not isinstance(path, str) or not path.startswith("/"):
            continue

        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():

            if not isinstance(method, str):
                continue

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
        "title": info.get("title", "Untitled API"),
        "servers": server_urls,
        "endpoints": endpoints,
        "total_endpoints": len(endpoints)
    }