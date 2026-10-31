"""AccessLens local-only end-to-end security demo API."""
from datetime import datetime, timezone
from html import escape
from threading import Lock
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
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

@app.get("/api/v1/scans/{scan_id}/report/html", response_class=HTMLResponse)
def readable_report(scan_id: str):
    """Human-readable, printable report of verified local synthetic checks."""
    job = get_scan(scan_id)
    if job["status"] != "completed":
        raise HTTPException(409, "Report requires completed check")
    e = lambda value: escape(str(value if value is not None else "—"), quote=True)
    findings = job.get("findings", [])
    failures = sum(f.get("verdict") == "FAIL" for f in findings)
    rows = []
    for index, f in enumerate(findings, 1):
        evidence = f.get("evidence", {})
        evidence_text = ", ".join(f"{e(k)}: {e(v)}" for k, v in evidence.items()) if isinstance(evidence, dict) else e(evidence)
        rows.append(
            f'<section class="finding"><h3>{index}. {e(f.get("type"))} <span class="severity">{e(f.get("severity"))}</span></h3>'
            f'<p><b>Endpoint:</b> {e(f.get("method"))} {e(f.get("endpoint"))}</p>'
            f'<p><b>OWASP / category:</b> {e(f.get("owasp_category", "Supporting check"))}</p>'
            f'<p><b>Verdict:</b> {e(f.get("verdict"))} &nbsp; <b>Confidence:</b> {e(f.get("confidence"))}</p>'
            f'<p>{e(f.get("description"))}</p><p><b>HTTP evidence:</b> {evidence_text}</p>'
            f'<p><b>Recommended fix:</b> {e(f.get("recommendation", "Review and retest the endpoint."))}</p></section>'
        )
    content = "".join(rows) or "<p>No checks returned by the local scanner.</p>"
    return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>AccessLens Security Report - {e(scan_id)}</title>
<style>
body{{font-family:Arial,sans-serif;background:#f3f6fa;color:#182235;line-height:1.55;margin:0}}
main{{max-width:900px;margin:36px auto;background:white;padding:44px;border-radius:12px;box-shadow:0 4px 24px #18223512}}
h1{{margin-bottom:0;color:#103a56}}h2{{border-bottom:2px solid #dbe5ed;padding-bottom:8px}}
.subtitle{{color:#526578;margin-top:2px}}.summary{{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}}
.metric{{background:#edf5f8;padding:16px 22px;border-radius:9px;min-width:140px}}
.metric strong{{display:block;font-size:28px}}.finding{{border:1px solid #dce5ed;border-left:5px solid #167c9e;border-radius:7px;padding:14px 20px;margin:16px 0;break-inside:avoid}}
.severity{{font-size:12px;background:#fbe3e3;color:#8c2222;padding:5px 9px;border-radius:10px}}
.notice{{background:#fff3d8;border-left:4px solid #d99a25;padding:14px;margin-top:24px}}
button{{background:#103a56;color:white;border:0;padding:11px 18px;border-radius:6px;cursor:pointer}}
@media print{{body{{background:white}}main{{margin:0;box-shadow:none;padding:0}}button{{display:none}}}}
</style></head><body><main>
<button onclick="window.print()">Print / Save as PDF</button>
<h1>AccessLens — API Security Assessment</h1>
<p class="subtitle">Human-readable local synthetic security report</p>
<h2>Assessment details</h2>
<p><b>Target:</b> {e(job.get("target_url"))}<br><b>Scan ID:</b> {e(scan_id)}<br>
<b>Created:</b> {e(job.get("created_at"))}<br><b>Status:</b> {e(job.get("status"))}<br>
<b>Approved paths:</b> {e(", ".join(job.get("approved_scope", [])))}</p>
<div class="summary"><div class="metric"><strong>{len(findings)}</strong>Checks</div>
<div class="metric"><strong>{failures}</strong>Failed</div>
<div class="metric"><strong>{len(findings)-failures}</strong>Other verdicts</div></div>
<h2>Findings, evidence and recommendations</h2>{content}
<div class="notice"><b>Scope limitation:</b> This report describes bounded HTTP checks against the intentionally vulnerable local ConnectedCar synthetic application. It is not a production penetration test or a certified VAPT report.</div>
</main></body></html>""")
