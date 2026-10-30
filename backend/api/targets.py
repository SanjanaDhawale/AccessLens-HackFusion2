from fastapi import APIRouter, HTTPException, status

from backend.schemas.target import (
    TargetRegistrationRequest,
    TargetRegistrationResponse,
)
from backend.services.target_service import (
    register_target,
    get_target,
    list_targets,
)

router = APIRouter(prefix="/targets", tags=["Targets"])


@router.post(
    "",
    response_model=TargetRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_target(request: TargetRegistrationRequest):
    try:
        return register_target(request)

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get("")
async def get_all_targets():
    targets = list_targets()
    return {
        "total_targets": len(targets),
        "targets": targets,
    }


@router.get("/{target_id}")
async def get_target_by_id(target_id: str):
    target = get_target(target_id)

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )

    return target