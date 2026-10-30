"""Local synthetic integration tests; no external network traffic."""
from fastapi.testclient import TestClient
from backend.main import app
from target.main import app as target_app

def test_backend_health():
    r=TestClient(app).get("/api/health")
    assert r.status_code==200 and r.json()["status"]=="ok"

def test_authorization_required():
    r=TestClient(app).post("/api/v1/scans",json={"target_url":"http://127.0.0.1:8001/vehicles/CAR-001","approved_scope":["/vehicles"],"authorized":False})
    assert r.status_code==403

def test_rejects_external_target():
    r=TestClient(app).post("/api/v1/scans",json={"target_url":"https://example.com/vehicles/CAR-001","approved_scope":["/vehicles"],"authorized":True})
    assert r.status_code==400

def test_rejects_wrong_port():
    r=TestClient(app).post("/api/v1/scans",json={"target_url":"http://127.0.0.1:9999/vehicles/CAR-001","approved_scope":["/vehicles"],"authorized":True})
    assert r.status_code==400

def test_demo_vulnerable_and_fixed():
    client=TestClient(target_app)
    client.post("/mode",json={"mode":"vulnerable"})
    vulnerable=client.get("/vehicles/CAR-001",headers={"X-Demo-User":"bob"})
    assert vulnerable.status_code==200
    client.post("/mode",json={"mode":"fixed"})
    fixed=client.get("/vehicles/CAR-001",headers={"X-Demo-User":"bob"})
    assert fixed.status_code==403
    client.post("/reset")
