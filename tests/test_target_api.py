from fastapi.testclient import TestClient

from backend.main import app
from backend.services import target_service

client = TestClient(app)


def setup_function():
    target_service._targets.clear()


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_target():
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
    assert response.json()["status"] == "REGISTERED"


def test_reject_unauthorized_target():
    response = client.post(
        "/api/targets",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": False,
            "authorized_hosts": ["example.com"],
            "allowed_paths": ["/"]
        }
    )

    assert response.status_code == 400


def test_list_targets():
    client.post(
        "/api/targets",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "authorized_hosts": ["example.com"],
            "allowed_paths": ["/"]
        }
    )

    response = client.get("/api/targets")

    assert response.status_code == 200
    assert response.json()["total_targets"] == 1


def test_get_target_by_id():
    created = client.post(
        "/api/targets",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "authorized_hosts": ["example.com"],
            "allowed_paths": ["/"]
        }
    )

    target_id = created.json()["target_id"]

    response = client.get(f"/api/targets/{target_id}")

    assert response.status_code == 200
    assert response.json()["target_id"] == target_id


def test_target_not_found():
    response = client.get("/api/targets/nonexistent")

    assert response.status_code == 404