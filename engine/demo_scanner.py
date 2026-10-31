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

async def scan_lab(target_url: str, approved_scope: list[str]) -> list[dict]:
    """Small, non-destructive HTTP checks against the synthetic localhost fixture."""
    from urllib.parse import urlsplit
    validate_target_url(target_url, ALLOWED_HOSTS)
    parsed = urlsplit(target_url)
    if parsed.port != ALLOWED_PORT:
        raise ValueError("Local synthetic lab only")
    base = f"{parsed.scheme}://{parsed.netloc}"
    checks = [
        ("API1:2023", "BOLA", "/vehicles/CAR-001", "alice", "bob", "vin"),
        ("API1:2023", "BOLA", "/profiles/alice", "alice", "bob", "user"),
        ("API5:2023", "Broken Function Level Authorization", "/admin/settings", "admin", "bob", "demo_feature"),
    ]
    findings = []
    async with httpx.AsyncClient(timeout=4, follow_redirects=False, trust_env=False) as client:
        for category, kind, path, owner, other, field in checks:
            if not any(s == "/" or path == s or (s.endswith("/") and path.startswith(s)) or (s in {"/vehicles", "/profiles", "/admin"} and path.startswith(s + "/")) for s in approved_scope):
                continue
            good = await client.get(base + path, headers={"X-Demo-User": owner})
            bad = await client.get(base + path, headers={"X-Demo-User": other})
            exposed = good.status_code == 200 and bad.status_code == 200 and bad.headers.get("content-type", "").startswith("application/json") and field in bad.json()
            findings.append({"id": f"LAB-{len(findings)+1:03}", "owasp_category": category, "type": kind,
                "endpoint": path, "method": "GET", "severity": "HIGH" if exposed else "INFO",
                "verdict": "FAIL" if exposed else "PASS" if good.status_code == 200 and bad.status_code in (401, 403) else "INCONCLUSIVE",
                "confidence": "CONFIRMED" if exposed or (good.status_code == 200 and bad.status_code in (401, 403)) else "LOW",
                "description": "Synthetic unauthorized role received protected data." if exposed else "Synthetic authorization check completed.",
                "evidence": {"authorized_status": good.status_code, "unauthorized_status": bad.status_code},
                "recommendation": "Enforce server-side object ownership or role checks for every request."})
        if any(s == "/" or s == "/profiles" or s == "/profiles/alice" for s in approved_scope):
            r = await client.get(base + "/profiles/alice", headers={"X-Demo-User": "alice"})
            exposed = r.status_code == 200 and "internal_debug_token" in r.json()
            findings.append({"id": "LAB-DATA", "owasp_category": "API3:2023", "type": "Excessive Property Exposure",
                "endpoint": "/profiles/alice", "method": "GET", "severity": "MEDIUM" if exposed else "INFO",
                "verdict": "FAIL" if exposed else "PASS" if r.status_code == 200 else "INCONCLUSIVE",
                "confidence": "CONFIRMED" if r.status_code == 200 else "LOW",
                "description": "Synthetic response contains an internal debug property." if exposed else "No synthetic debug property observed.",
                "evidence": {"status": r.status_code, "debug_property_present": exposed},
                "recommendation": "Return an explicit allowlist of public response properties."})
        if any(s in {"/", "/search"} for s in approved_scope):
            r = await client.get(base + "/search", params={"q": "x" * 100})
            missing = r.status_code == 200
            findings.append({"id": "LAB-INPUT", "owasp_category": "Input validation (supporting check)", "type": "Unbounded Search Input",
                "endpoint": "/search", "method": "GET", "severity": "LOW" if missing else "INFO",
                "verdict": "FAIL" if missing else "PASS" if r.status_code == 422 else "INCONCLUSIVE",
                "confidence": "CONFIRMED" if r.status_code in (200, 422) else "LOW",
                "description": "Synthetic search accepted 100-character input." if missing else "Synthetic search input length was checked.",
                "evidence": {"status": r.status_code, "input_length": 100},
                "recommendation": "Validate query length and types at the API boundary."})
    if not findings:
        raise ValueError("Approved scope does not include a supported synthetic lab endpoint")
    return findings
