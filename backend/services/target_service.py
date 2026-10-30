from urllib.parse import urlsplit

from backend.schemas.target import (
    TargetRegistrationRequest,
    TargetRegistrationResponse,
    create_target_record,
)

# Temporary in-memory storage.
# We will replace this with SQLAlchemy persistence.
_targets: dict[str, dict] = {}


def register_target(
    request: TargetRegistrationRequest,
) -> TargetRegistrationResponse:

    if not request.authorization_confirmed:
        raise ValueError("Explicit authorization confirmation is required.")

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
    _targets[record["target_id"]] = record

    return TargetRegistrationResponse(**record)


def get_target(target_id: str):
    return _targets.get(target_id)


def list_targets():
    return list(_targets.values())