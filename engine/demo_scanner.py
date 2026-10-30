"""Deterministic, bounded authorization check against the local synthetic target only."""
import httpx
from engine.scope import validate_target_url

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
ALLOWED_PORT = 8001

async def scan_demo(target_url: str, approved_scope: list[str]) -> list[dict]:
    from urllib.parse import urlsplit
    validate_target_url(target_url, ALLOWED_HOSTS)
    parsed = urlsplit(target_url)
    if parsed.port != ALLOWED_PORT:
        raise ValueError("Only the local ConnectedCar demo on port 8001 can be scanned")
    if parsed.path not in {"", "/", "/health", "/vehicles/CAR-001"}:
        raise ValueError("Use the ConnectedCar demo base URL or /health")
    if not any(path in {"/", "/vehicles", "/vehicles/CAR-001"} for path in approved_scope):
        raise ValueError("Approved scope must include /vehicles or /vehicles/CAR-001")
    base = f"{parsed.scheme}://{parsed.netloc}"
    url = base + "/vehicles/CAR-001"
    validate_target_url(url, ALLOWED_HOSTS)
    # Explicitly do not follow redirects; no credentials or real user records.
    async with httpx.AsyncClient(timeout=4, follow_redirects=False, trust_env=False) as client:
        alice = await client.get(url, headers={"X-Demo-User": "alice"})
        bob = await client.get(url, headers={"X-Demo-User": "bob"})
    if alice.status_code != 200 or alice.json().get("owner") != "alice":
        return [{"id": "CHECK-001", "type": "BOLA", "severity": "INFO", "endpoint": "/vehicles/CAR-001", "method": "GET", "verdict": "INCONCLUSIVE", "confidence": "LOW", "description": "Owner control request did not return expected synthetic fixture."}]
    if bob.status_code == 200 and bob.json().get("vin") == "CAR-001":
        return [{"id": "FIND-001", "type": "BOLA", "severity": "HIGH", "endpoint": "/vehicles/CAR-001", "method": "GET", "verdict": "FAIL", "confidence": "CONFIRMED", "description": "Synthetic user Bob can read Alice's vehicle. Enforce ownership authorization on every object request.", "evidence": {"owner_status": alice.status_code, "other_user_status": bob.status_code}}]
    if bob.status_code in (401, 403):
        return [{"id": "CHECK-001", "type": "BOLA", "severity": "INFO", "endpoint": "/vehicles/CAR-001", "method": "GET", "verdict": "PASS", "confidence": "CONFIRMED", "description": "Synthetic cross-owner request was rejected.", "evidence": {"owner_status": alice.status_code, "other_user_status": bob.status_code}}]
    return [{"id": "CHECK-001", "type": "BOLA", "severity": "INFO", "endpoint": "/vehicles/CAR-001", "method": "GET", "verdict": "INCONCLUSIVE", "confidence": "LOW", "description": "Unexpected response from synthetic target."}]
