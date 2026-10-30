from pathlib import Path

from integrations.openapi_parser import (
    parse_openapi,
    OpenAPIParseError,
)

MAX_SPEC_SIZE = 2 * 1024 * 1024

ALLOWED_EXTENSIONS = {".json", ".yaml", ".yml"}


def process_specification(filename: str, content: bytes) -> dict:
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Only JSON and YAML specifications are supported.")

    if not content:
        raise ValueError("Uploaded specification is empty.")

    if len(content) > MAX_SPEC_SIZE:
        raise ValueError("Specification exceeds the 2 MB size limit.")

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Specification must use UTF-8 encoding.") from exc

    try:
        result = parse_openapi(text)
    except OpenAPIParseError as exc:
        raise ValueError(str(exc)) from exc

    return result