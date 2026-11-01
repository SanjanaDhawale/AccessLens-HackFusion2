"""Local synthetic ConnectedCar target. Deliberately vulnerable demo mode only."""
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ConnectedCar Synthetic Demo", version="1.0")
MODE = {"value": "vulnerable"}
VEHICLES = {"CAR-001": {"vin": "CAR-001", "owner": "alice", "location": "DEMO-LOT-A"}, "CAR-002": {"vin": "CAR-002", "owner": "bob", "location": "DEMO-LOT-B"}}
ROLES = {"alice": "owner", "bob": "owner", "technician": "technician", "admin": "admin"}

class ModeRequest(BaseModel):
    mode: str

@app.get("/health")
def health():
    return {"status": "ok", "service": "connectedcar-demo", "mode": MODE["value"]}

@app.post("/reset")
def reset():
    MODE["value"] = "vulnerable"
    return {"mode": MODE["value"]}

@app.post("/mode")
def set_mode(request: ModeRequest):
    if request.mode not in {"vulnerable", "fixed"}:
        raise HTTPException(400, "Unknown mode")
    MODE["value"] = request.mode
    return {"mode": MODE["value"]}

@app.get("/vehicles/{vin}")
def get_vehicle(vin: str, x_demo_user: str | None = Header(default=None)):
    vehicle = VEHICLES.get(vin)
    if not vehicle:
        raise HTTPException(404, "Vehicle not found")
    if x_demo_user not in ROLES:
        raise HTTPException(401, "Synthetic demo identity required")
    if MODE["value"] == "fixed" and x_demo_user not in {vehicle["owner"], "admin"}:
        raise HTTPException(403, "Not authorized for this vehicle")
    return vehicle

# Additional deliberately vulnerable synthetic fixtures for a local OWASP teaching lab.
@app.get("/profiles/{user_id}")
def profile(user_id: str, x_demo_user: str | None = Header(default=None)):
    if user_id not in {"alice", "bob"}:
        raise HTTPException(404, "Unknown synthetic profile")
    if x_demo_user not in ROLES:
        raise HTTPException(401, "Synthetic identity required")
    if MODE["value"] == "fixed" and x_demo_user not in {user_id, "admin"}:
        raise HTTPException(403, "Profile access denied")
    result = {"user": user_id, "display_name": user_id.title()}
    if MODE["value"] == "vulnerable":
        result["internal_debug_token"] = "SYNTHETIC-DO-NOT-USE"
    return result

@app.get("/admin/settings")
def admin_settings(x_demo_user: str | None = Header(default=None)):
    if x_demo_user not in ROLES:
        raise HTTPException(401, "Synthetic identity required")
    if MODE["value"] == "fixed" and x_demo_user != "admin":
        raise HTTPException(403, "Admin role required")
    return {"demo_feature": True, "environment": "synthetic"}

@app.get("/search")
def search(q: str = ""):
    if MODE["value"] == "fixed" and len(q) > 80:
        raise HTTPException(422, "Search query exceeds 80 characters")
    return {"results": [], "query_length": len(q)}
