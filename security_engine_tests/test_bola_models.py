
import pytest
from pydantic import ValidationError

from security_engine.models import (
    BOLAIdentity,
    BOLAObjectReference,
    BOLATestCase,
    BOLATestConfig,
    ScanInput,
)


def valid_bola_config():
    return {
        "identities": [
            {"identity_id": "user_a", "credential_ref": "CRAPI_USER_A"},
            {"identity_id": "user_b", "credential_ref": "CRAPI_USER_B"},
        ],
        "object_reference": {
            "object_id": "vehicle-123",
            "object_type": "vehicle",
            "owner_identity_id": "user_a",
            "read_path": "/identity/api/v2/vehicle/vehicles/vehicle-123",
        },
        "test_cases": [
            {
                "case_id": "owner-check",
                "identity_id": "user_a",
                "access_type": "OWNER_ACCESS",
                "expected_access": "ALLOW",
            },
            {
                "case_id": "cross-account-check",
                "identity_id": "user_b",
                "access_type": "CROSS_ACCOUNT_ACCESS",
                "expected_access": "DENY",
            },
        ],
    }


def test_valid_bola_config_is_accepted():
    config = BOLATestConfig.model_validate(valid_bola_config())

    assert len(config.identities) == 2
    assert len(config.test_cases) == 2


def test_bola_config_rejects_missing_identity():
    data = valid_bola_config()
    data["identities"] = data["identities"][:1]

    with pytest.raises(ValidationError):
        BOLATestConfig.model_validate(data)


def test_bola_config_rejects_duplicate_credential_references():
    data = valid_bola_config()
    data["identities"][1]["credential_ref"] = "CRAPI_USER_A"

    with pytest.raises(ValidationError):
        BOLATestConfig.model_validate(data)


def test_bola_config_rejects_incorrect_owner_identity():
    data = valid_bola_config()
    data["test_cases"][0]["identity_id"] = "user_b"

    with pytest.raises(ValidationError):
        BOLATestConfig.model_validate(data)


def test_bola_config_rejects_incorrect_cross_account_identity():
    data = valid_bola_config()
    data["test_cases"][1]["identity_id"] = "user_a"

    with pytest.raises(ValidationError):
        BOLATestConfig.model_validate(data)


def test_bola_config_rejects_duplicate_case_ids():
    data = valid_bola_config()
    data["test_cases"][1]["case_id"] = "owner-check"

    with pytest.raises(ValidationError):
        BOLATestConfig.model_validate(data)


def test_bola_object_rejects_path_traversal():
    with pytest.raises(ValidationError):
        BOLAObjectReference.model_validate({
            "object_id": "vehicle-123",
            "object_type": "vehicle",
            "owner_identity_id": "user_a",
            "read_path": "/identity/../admin",
        })


def test_bola_identity_rejects_invalid_identity_name():
    with pytest.raises(ValidationError):
        BOLAIdentity.model_validate({
            "identity_id": "admin",
            "credential_ref": "CRAPI_USER_A",
        })


def test_scan_input_accepts_optional_bola_config():
    data = {
        "scan_id": "bola-test-001",
        "target_url": "http://localhost:8888",
        "authorized_hosts": ["localhost"],
        "allowed_paths": ["/identity/api/v2/vehicle"],
        "endpoints": [],
        "scan_profile": "OWASP_API_TOP_10_SAFE",
        "authorization_context": {
            "authorization_confirmed": True,
            "credentials_available": True,
        },
        "bola_test": valid_bola_config(),
    }

    scan_input = ScanInput.model_validate(data)

    assert scan_input.bola_test is not None
    assert len(scan_input.bola_test.identities) == 2


def test_scan_input_still_accepts_input_without_bola_config():
    data = {
        "scan_id": "normal-test-001",
        "target_url": "http://localhost:8888",
        "authorized_hosts": ["localhost"],
        "allowed_paths": ["/identity/api/v2/vehicle"],
        "endpoints": [],
        "scan_profile": "OWASP_API_TOP_10_SAFE",
        "authorization_context": {
            "authorization_confirmed": True,
            "credentials_available": False,
        },
    }

    scan_input = ScanInput.model_validate(data)

    assert scan_input.bola_test is None


from security_engine.scope_validator import (
    ScopeValidationError,
    validate_scan_scope,
)


def make_scan_input_with_bola():
    data = {
        "scan_id": "bola-scope-test",
        "target_url": "http://localhost:8888",
        "authorized_hosts": ["localhost"],
        "allowed_paths": ["/identity/api/v2/vehicle"],
        "endpoints": [],
        "scan_profile": "OWASP_API_TOP_10_SAFE",
        "authorization_context": {
            "authorization_confirmed": True,
            "credentials_available": True,
        },
        "bola_test": valid_bola_config(),
    }
    return ScanInput.model_validate(data)


def test_bola_object_path_outside_allowed_scope_is_rejected():
    scan_input = make_scan_input_with_bola()

    invalid_object = scan_input.bola_test.object_reference.model_copy(
        update={"read_path": "/identity/api/v2/user/profile"}
    )
    invalid_bola = scan_input.bola_test.model_copy(
        update={"object_reference": invalid_object}
    )
    modified_scan = scan_input.model_copy(
        update={"bola_test": invalid_bola}
    )

    with pytest.raises(ScopeValidationError):
        validate_scan_scope(modified_scan)


def test_bola_object_path_with_encoded_traversal_is_rejected():
    scan_input = make_scan_input_with_bola()

    invalid_object = scan_input.bola_test.object_reference.model_copy(
        update={
            "read_path": "/identity/api/v2/vehicle/%2e%2e/admin"
        }
    )
    invalid_bola = scan_input.bola_test.model_copy(
        update={"object_reference": invalid_object}
    )
    modified_scan = scan_input.model_copy(
        update={"bola_test": invalid_bola}
    )

    with pytest.raises(ScopeValidationError):
        validate_scan_scope(modified_scan)
