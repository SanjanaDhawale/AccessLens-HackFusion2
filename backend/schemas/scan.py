from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


ScanStatus = Literal[
    "QUEUED",
    "VALIDATING",
    "DISCOVERING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELLED"
]

ScanProfile = Literal[
    "OWASP_API_TOP_10_SAFE"
]


class ScanCreateRequest(BaseModel):
    target_id: str = Field(min_length=1)
    authorization_confirmed: bool
    scan_profile: ScanProfile = "OWASP_API_TOP_10_SAFE"
    specification_id: str | None = None


class ScanResponse(BaseModel):
    scan_id: str
    target_id: str
    specification_id: str | None
    status: ScanStatus
    progress: int = Field(ge=0, le=100)
    current_stage: str
    message: str
    created_at: datetime


class ScanEndpoint(BaseModel):
    path: str
    method: str
    source: Literal[
        "OPENAPI",
        "AUTHORIZED_DISCOVERY",
        "USER_PROVIDED"
    ]


class ScanEndpointResponse(BaseModel):
    scan_id: str
    total_endpoints: int
    endpoints: list[ScanEndpoint]


class ScanFinding(BaseModel):
    id: str
    owasp_id: str
    title: str
    severity: Literal[
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO"
    ]
    status: Literal[
        "PASS",
        "FAIL",
        "INCONCLUSIVE",
        "NOT_APPLICABLE"
    ]
    confidence: Literal[
        "CONFIRMED",
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNKNOWN"
    ]
    endpoint: str
    method: str
    evidence_id: str | None = None
    rationale: str
    remediation: str


class ScanFindingResponse(BaseModel):
    scan_id: str
    total_findings: int
    findings: list[ScanFinding]


def create_scan_record(
    target_id: str,
    specification_id: str | None
) -> dict:
    return {
        "scan_id": str(uuid4()),
        "target_id": target_id,
        "specification_id": specification_id,
        "status": "QUEUED",
        "progress": 0,
        "current_stage": "QUEUED",
        "message": "Assessment queued successfully.",
        "created_at": datetime.now(timezone.utc)
    }