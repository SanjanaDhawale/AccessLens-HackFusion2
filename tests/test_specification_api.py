from fastapi.testclient import TestClient

from backend.main import app
from backend.api import specifications
from backend.services import target_service

client = TestClient(app)


VALID_SPEC = """
openapi: 3.0.3
info:
  title: AccessLens Test API
  version: 1.0.0
servers:
  - url: https://example.com
paths:
  /api/users:
    get:
      summary: Get users
      operationId: getUsers
      responses:
        '200':
          description: Success
    post:
      summary: Create user
      operationId: createUser
      responses:
        '201':
          description: Created
  /api/users/{user_id}:
    get:
      summary: Get user by ID
      operationId: getUser
      responses:
        '200':
          description: Success
"""


def setup_function():
    specifications._specifications.clear()
    target_service._targets.clear()


def create_authorized_target():
    response = client.post(
        "/api/targets",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "authorized_hosts": ["example.com"],
            "allowed_paths": ["/api"]
        }
    )

    assert response.status_code == 201
    return response.json()["target_id"]


def upload_specification(
    content=VALID_SPEC,
    filename="openapi.yaml",
    target_id=None,
    authorization_confirmed="true"
):
    if target_id is None:
        target_id = create_authorized_target()

    return client.post(
        "/api/targets/specification",
        data={
            "target_id": target_id,
            "authorization_confirmed": authorization_confirmed
        },
        files={
            "file": (
                filename,
                content,
                "application/x-yaml"
            )
        }
    )


def test_upload_valid_specification():
    response = upload_specification()

    assert response.status_code == 201
    assert response.json()["status"] == "PARSED"
    assert response.json()["endpoint_count"] == 3
    assert response.json()["target_id"] is not None


def test_reject_invalid_specification():
    response = upload_specification(
        content="invalid: [yaml"
    )

    assert response.status_code == 400


def test_reject_unsupported_file():
    response = upload_specification(
        content="sample content",
        filename="test.txt"
    )

    assert response.status_code == 400


def test_reject_empty_file():
    response = upload_specification(content="")

    assert response.status_code == 400


def test_reject_unregistered_target():
    response = upload_specification(
        target_id="nonexistent-target"
    )

    assert response.status_code == 404


def test_reject_missing_authorization():
    response = upload_specification(
        authorization_confirmed="false"
    )

    assert response.status_code == 400


def test_reject_server_outside_authorized_scope():
    external_spec = VALID_SPEC.replace(
        "https://example.com",
        "https://unauthorized.example.org"
    )

    response = upload_specification(content=external_spec)

    assert response.status_code == 400


def test_reject_endpoint_outside_allowed_paths():
    external_path_spec = VALID_SPEC.replace(
        "/api/users",
        "/admin/users"
    )

    response = upload_specification(
        content=external_path_spec
    )

    assert response.status_code == 400


def test_get_specification():
    created = upload_specification()

    specification_id = created.json()["specification_id"]

    response = client.get(
        f"/api/targets/specification/{specification_id}"
    )

    assert response.status_code == 200
    assert response.json()["endpoint_count"] == 3


def test_specification_not_found():
    response = client.get(
        "/api/targets/specification/nonexistent"
    )

    assert response.status_code == 404