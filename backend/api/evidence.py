from fastapi import APIRouter, HTTPException, status

from backend.schemas.evidence import EvidenceCreateRequest
from backend.services.evidence_service import (
    create_evidence,
    get_evidence,
    list_scan_evidence,
)

router = APIRouter(prefix="/evidence", tags=["Evidence"])


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_evidence_endpoint(request: EvidenceCreateRequest):
    return create_evidence(request)


@router.get("/{evidence_id}")
async def get_evidence_endpoint(evidence_id: str):
    evidence = get_evidence(evidence_id)

    if not evidence:
        raise HTTPException(
            status_code=404,
            detail="Evidence not found."
        )

    return evidence