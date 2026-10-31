"""AccessLens local-only end-to-end security demo API."""
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from engine.scope import ScopeViolation, validate_target_url
from engine.demo_scanner import scan_demo, scan_lab

app = FastAPI(title="AccessLens API", version="1.0.0")
app.add_middleware(CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500","http://localhost:5500","http://127.0.0.1:3001","http://localhost:3001"],
    allow_credentials=False, allow_methods=["GET","POST"], allow_headers=["Content-Type"])
_jobs: dict[str, dict] = {}
_lock = Lock()
DEMO_HOSTS = {"127.0.0.1", "localhost"}

class ScanRequest(BaseModel):
    target_url: str = Field(min_length=10, max_length=2048)
    openapi_url: str | None = None
    approved_scope: list[str] = Field(min_length=1, max_length=20)
    mode: str = "vulnerable"
    authorized: bool = False

    @field_validator("approved_scope")
    @classmethod
    def validate_paths(cls, paths):
        if any(not p.startswith("/") or p.startswith("//") or "?" in p or "#" in p for p in paths):
            raise ValueError("Approved paths must start with / and cannot contain query strings")
        return paths

def check_target(url):
    try:
        validate_target_url(url, DEMO_HOSTS)
        parsed = urlsplit(url)
        if parsed.port != 8001 or parsed.username or parsed.password or parsed.fragment:
            raise ScopeViolation("Only the local ConnectedCar demo at port 8001 is allowed")
    except (ScopeViolation, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc

@app.get("/api/v1/demo/endpoints")
def demo_endpoints():
    return {
        "application": "ConnectedCar Synthetic Demo",
        "base_url": "http://127.0.0.1:8001",
        "synthetic_only": True,
        "owasp_2023_tested": ["API1:2023 Broken Object Level Authorization", "API3:2023 Broken Object Property Level Authorization (exposure check)", "API5:2023 Broken Function Level Authorization"],
        "endpoints": [
            {"method": "GET", "path": "/health", "tested": False},
            {"method": "GET", "path": "/vehicles/{vin}", "tested": True, "roles": ["owner", "admin"], "check": "BOLA owner vs non-owner"},
            {"method": "GET", "path": "/profiles/{user_id}", "tested": True},
            {"method": "GET", "path": "/admin/settings", "tested": True},
            {"method": "GET", "path": "/search", "tested": True},
            {"method": "POST", "path": "/mode", "tested": False},
            {"method": "POST", "path": "/reset", "tested": False}
        ]
    }

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "accesslens-api", "demo_mode": True}

@app.get("/api/v1/scans")
def list_scans():
    with _lock:
        return {"items": list(_jobs.values())}

@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str):
    with _lock:
        job = _jobs.get(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found")
    return job

@app.post("/api/v1/scans", status_code=202)
async def create_scan(request: ScanRequest):
    if not request.authorized:
        raise HTTPException(403, "Explicit authorization required")
    check_target(request.target_url)
    if request.openapi_url:
        raise HTTPException(400, "Remote OpenAPI URLs are not supported; use the local /openapi.json inventory")
    if request.mode not in {"vulnerable", "fixed"}:
        raise HTTPException(400, "Unsupported mode")
    job = {"id": str(uuid4()), "target_url": request.target_url,
           "approved_scope": request.approved_scope, "mode": request.mode,
           "status": "running", "created_at": datetime.now(timezone.utc).isoformat(),
           "findings": [], "message": "Running scoped synthetic OWASP lab checks"}
    with _lock:
        _jobs[job["id"]] = job
    try:
        findings = await scan_lab(request.target_url, request.approved_scope)
        job["findings"] = findings
        job["status"] = "completed"
        job["message"] = "Scoped synthetic API checks completed"
    except (ValueError, ScopeViolation) as exc:
        job["status"] = "rejected"
        job["message"] = str(exc)
    except Exception:
        job["status"] = "failed"
        job["message"] = "Synthetic target unavailable or returned unexpected data"
    return job

@app.get("/api/v1/scans/{scan_id}/findings")
def get_findings(scan_id: str):
    job = get_scan(scan_id)
    return {"items": job["findings"], "scan_id": scan_id}

@app.get("/api/v1/scans/{scan_id}/report")
def report(scan_id: str):
    job = get_scan(scan_id)
    if job["status"] != "completed":
        raise HTTPException(409, "Report requires completed check")
    return {"scan_id": scan_id, "demo_only": True, "target_url": job["target_url"],
            "application": "ConnectedCar Synthetic Demo",
            "methodology": "Owner vs non-owner HTTP GET comparison",
            "owasp_2023_tested": ["API1:2023 Broken Object Level Authorization"],
            "scope": job["approved_scope"], "created_at": job["created_at"],
            "recommendations": ["Enforce server-side object ownership checks on every request.", "Return 403 for cross-owner requests.", "Retest with the fixed synthetic target."],
            "status": job["status"], "findings": job["findings"],
            "disclaimer": "Synthetic local ConnectedCar test only. Not a production VAPT report."}
