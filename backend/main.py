from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.reports import router as reports_router
from backend.api.targets import router as targets_router
from backend.api.specifications import router as specifications_router
from backend.api.scans import router as scans_router
from backend.api.evidence import router as evidence_router


app = FastAPI(
    title="AccessLens API",
    description="AI-Powered Conversational API Security Assessment Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# Register all API routers AFTER app initialization
app.include_router(targets_router, prefix="/api")
app.include_router(specifications_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(evidence_router, prefix="/api")
app.include_router(reports_router, prefix="/api")

@app.get("/")
async def root():
    return {
        "message": "Welcome to AccessLens",
        "status": "operational"
    }


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "accesslens-api",
        "version": "1.0.0"
    }