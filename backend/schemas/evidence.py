from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EvidenceCreateRequest(BaseModel):
    scan_id: str = Field(min_length=1)
    finding_id: str = Field(min_length=1)
    check_id: str = Field(min_length=1)

    request: dict[str, Any]
    response: dict[str, Any]

    notes: str = ""


class EvidenceResponse(BaseModel):
    evidence_id: str
    scan_id: str
    finding_id: str
    check_id: str

    timestamp: datetime

    request: dict[str, Any]
    response: dict[str, Any]

    notes: str


def create_evidence_record(request: EvidenceCreateRequest) -> dict:
    return {
        "evidence_id": str(uuid4()),
        "scan_id": request.scan_id,
        "finding_id": request.finding_id,
        "check_id": request.check_id,
        "timestamp": datetime.now(timezone.utc),
        "request": request.request,
        "response": request.response,
        "notes": request.notes
    }