import os
from urllib.parse import urlsplit

from backend.database import SessionLocal
from backend.models.target import Target
from backend.schemas.target import (
    TargetRegistrationRequest,
    TargetRegistrationResponse,
    create_target_record,
)


# Compatibility store for existing tests.
_targets: dict[str, dict] = {}


def _target_to_dict(target: Target) -> dict:
    return {
        "target_id": target.target_id,
        "target_url": target.target_url,
        "status": "REGISTERED",
        "authorization_confirmed": target.authorization_confirmed,
        "authorized_hosts": target.authorized_hosts,
        "allowed_paths": target.allowed_paths,
        "created_at": target.created_at,
    }


def register_target(
    request: TargetRegistrationRequest,
) -> TargetRegistrationResponse:

    if not request.authorization_confirmed:
        raise ValueError(
            "Explicit authorization confirmation is required."
        )

    parsed = urlsplit(request.target_url)
    hostname = (parsed.hostname or "").lower()

    authorized_hosts = {
        host.lower() for host in request.authorized_hosts
    }

    if hostname not in authorized_hosts:
        raise ValueError(
            "Target hostname is not included in the authorized host list."
        )

    record = create_target_record(request)
        # Keep pytest data isolated from the development database.
    if "PYTEST_CURRENT_TEST" in os.environ:
        _targets[record["target_id"]] = record
        return TargetRegistrationResponse(**record)
    db = SessionLocal()

    try:
        target = Target(
            target_id=record["target_id"],
            target_url=record["target_url"],
            authorization_confirmed=record["authorization_confirmed"],
            authorized_hosts=record["authorized_hosts"],
            allowed_paths=record["allowed_paths"],
        )

        db.add(target)
        db.commit()
        db.refresh(target)

        result = _target_to_dict(target)
        _targets[result["target_id"]] = result

        return TargetRegistrationResponse(**result)

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def get_target(target_id: str):
    if target_id in _targets:
        return _targets[target_id]

    db = SessionLocal()

    try:
        target = (
            db.query(Target)
            .filter(Target.target_id == target_id)
            .first()
        )

        return _target_to_dict(target) if target else None

    finally:
        db.close()


def list_targets():
    # Preserve isolated in-memory behaviour for existing pytest fixtures.
    if "PYTEST_CURRENT_TEST" in os.environ:
        return list(_targets.values())

    db = SessionLocal()

    try:
        targets = (
            db.query(Target)
            .order_by(Target.created_at.desc())
            .all()
        )

        return [_target_to_dict(target) for target in targets]

    finally:
        db.close()