"""FastAPI entry point for the AccessLens control plane."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AccessLens API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "accesslens-api"}

@app.get("/api/v1/scans")
def list_scans():
    return {"items": [], "message": "Scan storage not implemented yet"}

@app.post("/api/v1/scans")
def create_scan():
    # TODO: validate scope and OpenAPI input before starting a scan.
    return {"status": "not_implemented", "message": "Scan orchestration is being implemented"}
