from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="AccessLens API",
    description="AI-Powered Conversational API Security Assessment Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


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