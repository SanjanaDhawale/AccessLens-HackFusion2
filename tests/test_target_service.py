import pytest

from backend.schemas.target import TargetRegistrationRequest
from backend.services import target_service


@pytest.fixture(autouse=True)
def reset_target_storage(monkeypatch):
    monkeypatch.setattr(target_service, "_targets", {})


def create_valid_request():
    return TargetRegistrationRequest(
        target_url="https://example.com",
        authorization_confirmed=True,
        authorized_hosts=["example.com"],
        allowed_paths=["/api"]
    )


def test_register_authorized_target():
    request = create_valid_request()

    result = target_service.register_target(request)

    assert result.status == "REGISTERED"
    assert result.target_url == "https://example.com"
    assert result.authorization_confirmed is True
    assert result.authorized_hosts == ["example.com"]
    assert result.allowed_paths == ["/api"]


def test_reject_target_without_authorization():
    request = TargetRegistrationRequest(
        target_url="https://example.com",
        authorization_confirmed=False,
        authorized_hosts=["example.com"],
        allowed_paths=["/"]
    )

    with pytest.raises(ValueError, match="authorization"):
        target_service.register_target(request)


def test_reject_unauthorized_hostname():
    request = TargetRegistrationRequest(
        target_url="https://example.com",
        authorization_confirmed=True,
        authorized_hosts=["other-example.com"],
        allowed_paths=["/"]
    )

    with pytest.raises(ValueError, match="authorized host"):
        target_service.register_target(request)


def test_get_registered_target():
    request = create_valid_request()

    result = target_service.register_target(request)

    stored_target = target_service.get_target(result.target_id)

    assert stored_target is not None
    assert stored_target["target_id"] == result.target_id


def test_list_registered_targets():
    request = create_valid_request()

    target_service.register_target(request)

    targets = target_service.list_targets()

    assert len(targets) == 1
    assert targets[0]["target_url"] == "https://example.com"