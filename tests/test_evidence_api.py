import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.evidence_service import clear_evidence_store
from backend.services.scan_service import _scans

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_evidence():
    clear_evidence_store()
    _scans.clear()
    yield
    clear_evidence_store()
    _scans.clear()


def test_create_evidence():
    response = client.post(
        "/api/evidence",
        json={
            "scan_id": "SCAN-001",
            "finding_id": "FIND-001",
            "check_id": "API8-001",
            "request": {
                "headers": {
                    "Authorization": "Bearer secret123"
                }
            },
            "response": {
                "body": {
                    "password": "admin123",
                    "username": "test"
                }
            },
            "notes": "Security configuration evidence"
        }
    )

    assert response.status_code == 201

    data = response.json()

    assert data["evidence_id"]
    assert data["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert data["response"]["body"]["password"] == "[REDACTED]"
    assert data["response"]["body"]["username"] == "test"


def test_get_evidence():
    created = client.post(
        "/api/evidence",
        json={
            "scan_id": "SCAN-002",
            "finding_id": "FIND-002",
            "check_id": "API8-002",
            "request": {},
            "response": {},
            "notes": "Test evidence"
        }
    )

    evidence_id = created.json()["evidence_id"]

    response = client.get(f"/api/evidence/{evidence_id}")

    assert response.status_code == 200
    assert response.json()["evidence_id"] == evidence_id


def test_evidence_not_found():
    response = client.get("/api/evidence/unknown-id")

    assert response.status_code == 404


def test_get_evidence_for_unknown_scan():
    response = client.get("/api/scans/unknown-scan/evidence")

    assert response.status_code == 404