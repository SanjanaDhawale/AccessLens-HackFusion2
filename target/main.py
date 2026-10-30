"""ConnectedCar demo target. Use synthetic data only."""
from fastapi import FastAPI

app = FastAPI(title="ConnectedCar Demo API", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok", "service": "connectedcar-demo"}

# TODO: Member 1 — users/roles, login, vehicle endpoints, vulnerable/fixed modes,
# reset endpoint, synthetic fixtures, and OpenAPI documentation.
