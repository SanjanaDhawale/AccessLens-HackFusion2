import pytest

from integrations.openapi_parser import (
    parse_openapi,
    OpenAPIParseError
)


def test_parse_openapi_endpoints():
    content = """
openapi: 3.0.3
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      operationId: getUsers
      summary: Get users
    post:
      operationId: createUser
  /users/{user_id}:
    get:
      operationId: getUser
"""

    result = parse_openapi(content)

    assert result["title"] == "Test API"
    assert result["total_endpoints"] == 3

    methods = {
        (endpoint["path"], endpoint["method"])
        for endpoint in result["endpoints"]
    }

    assert ("/users", "GET") in methods
    assert ("/users", "POST") in methods
    assert ("/users/{user_id}", "GET") in methods


def test_reject_invalid_specification():
    with pytest.raises(OpenAPIParseError):
        parse_openapi("not an openapi document")