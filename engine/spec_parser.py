"""OpenAPI parsing and endpoint normalization."""
from pathlib import Path
from typing import Any
import yaml

def load_openapi(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as file:
        spec = yaml.safe_load(file)
    if not isinstance(spec, dict) or "paths" not in spec:
        raise ValueError("OpenAPI document must contain a paths section")
    return spec

def discover_endpoints(spec: dict[str, Any]) -> list[dict[str, Any]]:
    # TODO: normalize path, method, operationId, parameters, and security metadata.
    return []
