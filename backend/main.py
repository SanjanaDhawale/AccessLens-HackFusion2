"""AccessLens control plane: scoped scan request intake (no active scanning yet)."""
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from engine.scope import ScopeViolation, validate_target_url

app = FastAPI(title="AccessLens API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:3001", "http://localhost:3001"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# Development-only storage. Restarting the server clears jobs.
_jobs: dict[str, dict] = {}
_lock = Lock()
# Until authenticated scope ownership verification exists, ONLY loopback demo
# targets can be submitted. Never broaden this based on user-provided input.
DEMO_HOSTS = {"127.0.0.1", "localhost"}


class ScanRequest(BaseModel):
    target_url: str = Field(min_length=10, max_length=2048)
    openapi_url: str | None = None
    approved_scope: list[str] = Field(min_length=1, max_length=100)
    mode: str = "vulnerable"
    authorized: bool = False

    @field_validator("approved_scope")
    @classmethod
    def check_paths(cls, value: list[str]) -> list[str]:
        if any(not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path for path in value):
            raise ValueError("Each approved scope entry must be an absolute API path beginning with /")
        return value


def require_local_scope(url: str) -> None:
    try:
        validate_target_url(url, DEMO_HOSTS)
        parsed = urlsplit(url)
        if parsed.fragment or parsed.username or parsed.password:
            raise ScopeViolation("Fragments and embedded credentials are not allowed")
    except (ScopeViolation, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "accesslens-api"}


@app.get("/api/v1/scans")
def list_scans():
    with _lock:
        return {"items": list(_jobs.values())}


@app.post("/api/v1/scans", status_code=202)
def create_scan(request: ScanRequest):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Explicit scan authorization is required")
    require_local_scope(request.target_url)
    if request.openapi_url:
        require_local_scope(request.openapi_url)
        if urlsplit(request.openapi_url).hostname != urlsplit(request.target_url).hostname:
            raise HTTPException(status_code=400, detail="OpenAPI host must match target host")
    if request.mode not in {"vulnerable", "fixed"}:
        raise HTTPException(status_code=400, detail="Unsupported demo mode")
    # Intake only. No outbound requests, active scans, or findings.
    job = {
        "id": str(uuid4()),
        "target_url": request.target_url,
        "approved_scope": request.approved_scope,
        "mode": request.mode,
        "status": "awaiting_engine",
        "message": "Request recorded. Scan execution is not implemented.",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "findings": [],
    }
    with _lock:
        _jobs[job["id"]] = job
    return job


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str):
    with _lock:
        job = _jobs.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan request not found")
    return job
