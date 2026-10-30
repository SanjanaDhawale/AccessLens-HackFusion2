from fastapi.testclient import TestClient
from datetime import datetime
from pydantic import BaseModel
from backend.main import app
from backend.api import specifications
from backend.services import target_service, scan_service

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
      responses:
        '200':
          description: Success
    post:
      summary: Create user
      responses:
        '201':
          description: Created
  /api/users/{user_id}:
    get:
      summary: Get user
      responses:
        '200':
          description: Success
"""


def setup_function():
    specifications._specifications.clear()
    target_service._targets.clear()
    scan_service._scans.clear()
    scan_service._scan_endpoints.clear()
    scan_service._scan_findings.clear()


def create_target():
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


def create_specification(target_id):
    response = client.post(
        "/api/targets/specification",
        data={
            "target_id": target_id,
            "authorization_confirmed": "true"
        },
        files={
            "file": (
                "openapi.yaml",
                VALID_SPEC,
                "application/x-yaml"
            )
        }
    )

    assert response.status_code == 201
    return response.json()["specification_id"]


def create_scan_request(target_id, specification_id):
    return {
        "target_id": target_id,
        "authorization_confirmed": True,
        "specification_id": specification_id,
        "scan_profile": "OWASP_API_TOP_10_SAFE"
    }


def test_create_scan():
    target_id = create_target()
    specification_id = create_specification(target_id)

    response = client.post(
        "/api/scans",
        json=create_scan_request(target_id, specification_id)
    )

    assert response.status_code == 201
    assert response.json()["status"] == "QUEUED"
    assert response.json()["progress"] == 0
    assert response.json()["target_id"] == target_id


def test_reject_scan_without_authorization():
    target_id = create_target()
    specification_id = create_specification(target_id)

    request = create_scan_request(target_id, specification_id)
    request["authorization_confirmed"] = False

    response = client.post("/api/scans", json=request)

    assert response.status_code == 400


def test_reject_unregistered_target():
    response = client.post(
        "/api/scans",
        json=create_scan_request("invalid-target", "invalid-spec")
    )

    assert response.status_code == 400


def test_reject_missing_specification():
    target_id = create_target()

    response = client.post(
        "/api/scans",
        json={
            "target_id": target_id,
            "authorization_confirmed": True,
            "scan_profile": "OWASP_API_TOP_10_SAFE"
        }
    )

    assert response.status_code == 400


def test_reject_invalid_specification():
    target_id = create_target()

    response = client.post(
        "/api/scans",
        json=create_scan_request(target_id, "invalid-spec")
    )

    assert response.status_code == 400


def test_reject_specification_belonging_to_another_target():
    target_id_1 = create_target()
    specification_id = create_specification(target_id_1)

    target_id_2 = create_target()

    response = client.post(
        "/api/scans",
        json=create_scan_request(target_id_2, specification_id)
    )

    assert response.status_code == 400


def test_get_scan_status():
    target_id = create_target()
    specification_id = create_specification(target_id)

    created = client.post(
        "/api/scans",
        json=create_scan_request(target_id, specification_id)
    )

    scan_id = created.json()["scan_id"]

    response = client.get(f"/api/scans/{scan_id}")

    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id
    assert response.json()["status"] == "QUEUED"


def test_get_scan_endpoints():
    target_id = create_target()
    specification_id = create_specification(target_id)

    created = client.post(
        "/api/scans",
        json=create_scan_request(target_id, specification_id)
    )

    scan_id = created.json()["scan_id"]

    response = client.get(
        f"/api/scans/{scan_id}/endpoints"
    )

    assert response.status_code == 200
    assert response.json()["total_endpoints"] == 3


def test_get_scan_findings():
    target_id = create_target()
    specification_id = create_specification(target_id)

    created = client.post(
        "/api/scans",
        json=create_scan_request(target_id, specification_id)
    )

    scan_id = created.json()["scan_id"]

    response = client.get(
        f"/api/scans/{scan_id}/findings"
    )

    assert response.status_code == 200
    assert response.json()["total_findings"] == 0


def test_reject_unknown_scan():
    response = client.get("/api/scans/invalid-scan")

    assert response.status_code == 404


def test_reject_unknown_scan_endpoints():
    response = client.get(
        "/api/scans/invalid-scan/endpoints"
    )

    assert response.status_code == 404


def test_reject_unknown_scan_findings():
    response = client.get(
        "/api/scans/invalid-scan/findings"
    )

    assert response.status_code == 404
    from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EvidenceCreateRequest(BaseModel):
    scan_id: str = Field(min_length=1)
    finding_id: str = Field(min_length=1)
    check_id: str = Field(min_length=1)

    request: dict[str, Any]
    response: dict[str, Any]

    notes: str = ""


class EvidenceResponse(BaseModel):
    evidence_id: str
    scan_id: str
    finding_id: str
    check_id: str

    timestamp: datetime

    request: dict[str, Any]
    response: dict[str, Any]

    notes: str


def create_evidence_record(request: EvidenceCreateRequest) -> dict:
    return {
        "evidence_id": str(uuid4()),
        "scan_id": request.scan_id,
        "finding_id": request.finding_id,
        "check_id": request.check_id,
        "timestamp": datetime.now(timezone.utc),
        "request": request.request,
        "response": request.response,
        "notes": request.notes
    }