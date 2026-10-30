
import json
from unittest.mock import MagicMock, patch

import pytest

from security_engine.detectors.api3_broken_object_property import (
    API3BrokenObjectPropertyDetector,
)
from security_engine.models import (
    AuthorizationContext,
    BOPLAPropertyTest,
    BOPLATestConfig,
    CheckStatus,
    Endpoint,
    EndpointSource,
    ScanInput,
)


@pytest.fixture
def scan_input():
    return ScanInput(
        scan_id="api3-test",
        target_url="http://localhost:8888",
        authorized_hosts=["localhost"],
        allowed_paths=["/api/v1/profile"],
        endpoints=[
            Endpoint(
                path="/api/v1/profile",
                method="GET",
                source=EndpointSource.USER_PROVIDED,
            )
        ],
        scan_profile="OWASP_API_TOP_10_SAFE",
        authorization_context=AuthorizationContext(
            authorization_confirmed=True,
            credentials_available=True,
        ),
        bopla_test=BOPLATestConfig(
            tests=[
                BOPLAPropertyTest(
                    test_id="BOPLA-001",
                    endpoint_path="/api/v1/profile",
                    credential_ref="CRAPI_USER_A",
                    forbidden_properties=[
                        "salary",
                        "profile.private_notes",
                    ],
                )
            ]
        ),
    )


def mock_response(status_code, body):
    response = MagicMock()
    response.status_code = status_code
    response.body_excerpt = body
    response.headers = {"Content-Type": "application/json"}
    return response


@patch(
    "security_engine.detectors.api3_broken_object_property."
    "resolve_bearer_token",
    return_value="test-token",
)
@patch(
    "security_engine.detectors.api3_broken_object_property."
    "SafeRequestClient"
)
def test_sensitive_property_exposure(
    mock_client_class,
    mock_token,
    scan_input,
):
    mock_client = mock_client_class.return_value
    mock_client.request.return_value = mock_response(
        200,
        json.dumps({
            "id": 101,
            "salary": 50000,
            "profile": {
                "private_notes": "private value"
            },
        }),
    )

    coverage, findings, evidence = (
        API3BrokenObjectPropertyDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.FAIL
    assert len(findings) == 1
    assert len(evidence) == 1
    assert findings[0].evidence_id == evidence[0].evidence_id
    assert evidence[0].finding_id == findings[0].id

    mock_client.request.assert_called_once()
    assert mock_client.request.call_args.args[0] == "GET"


@patch(
    "security_engine.detectors.api3_broken_object_property."
    "resolve_bearer_token",
    return_value="test-token",
)
@patch(
    "security_engine.detectors.api3_broken_object_property."
    "SafeRequestClient"
)
def test_sensitive_properties_not_present(
    mock_client_class,
    mock_token,
    scan_input,
):
    mock_client = mock_client_class.return_value
    mock_client.request.return_value = mock_response(
        200,
        json.dumps({"id": 101, "name": "Test User"}),
    )

    coverage, findings, evidence = (
        API3BrokenObjectPropertyDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.PASS
    assert findings == []
    assert evidence == []


@patch(
    "security_engine.detectors.api3_broken_object_property."
    "resolve_bearer_token",
    return_value="test-token",
)
@patch(
    "security_engine.detectors.api3_broken_object_property."
    "SafeRequestClient"
)
def test_unauthorized_response_is_inconclusive(
    mock_client_class,
    mock_token,
    scan_input,
):
    mock_client = mock_client_class.return_value
    mock_client.request.return_value = mock_response(403, "{}")

    coverage, findings, evidence = (
        API3BrokenObjectPropertyDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


@patch(
    "security_engine.detectors.api3_broken_object_property."
    "resolve_bearer_token",
    return_value="test-token",
)
@patch(
    "security_engine.detectors.api3_broken_object_property."
    "SafeRequestClient"
)
def test_invalid_json_is_inconclusive(
    mock_client_class,
    mock_token,
    scan_input,
):
    mock_client = mock_client_class.return_value
    mock_client.request.return_value = mock_response(
        200,
        "not-json",
    )

    coverage, findings, evidence = (
        API3BrokenObjectPropertyDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_missing_configuration_is_inconclusive(scan_input):
    scan_input.bopla_test = None

    coverage, findings, evidence = (
        API3BrokenObjectPropertyDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_unconfirmed_authorization_is_inconclusive(scan_input):
    scan_input.authorization_context.authorization_confirmed = False

    coverage, findings, evidence = (
        API3BrokenObjectPropertyDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []
