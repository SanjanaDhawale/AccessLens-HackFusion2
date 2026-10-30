from fastapi import APIRouter, HTTPException, status
from backend.services.evidence_service import list_scan_evidence
from backend.schemas.scan import ScanCreateRequest
from backend.services.scan_service import (
    create_scan,
    get_scan,
    list_scan_endpoints,
    list_scan_findings,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", status_code=status.HTTP_201_CREATED)
async def start_scan(request: ScanCreateRequest):
    try:
        return create_scan(
            target_id=request.target_id,
            authorization_confirmed=request.authorization_confirmed,
            specification_id=request.specification_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get("/{scan_id}")
async def get_scan_status(scan_id: str):
    scan = get_scan(scan_id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    return scan


@router.get("/{scan_id}/endpoints")
async def get_scan_endpoints(scan_id: str):
    result = list_scan_endpoints(scan_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    return result


@router.get("/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    result = list_scan_findings(scan_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    return result
@router.get("/{scan_id}/evidence")
async def get_scan_evidence(scan_id: str):
    scan = get_scan(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found."
        )

    return {
        "scan_id": scan_id,
        "total_evidence": len(list_scan_evidence(scan_id)),
        "evidence": list_scan_evidence(scan_id)
    }