
from unittest.mock import MagicMock, patch

import pytest

from security_engine.detectors.api5_broken_function_authorization import (
    API5BrokenFunctionAuthorizationDetector,
)
from security_engine.models import (
    AuthorizationContext,
    CheckStatus,
    Endpoint,
    EndpointSource,
    ScanInput,
)


@pytest.fixture
def scan_input():
    return ScanInput(
        scan_id="api5-test",
        target_url="http://localhost:8888",
        authorized_hosts=["localhost"],
        allowed_paths=["/api/v1/admin"],
        endpoints=[
            Endpoint(
                path="/api/v1/admin",
                method="GET",
                source=EndpointSource.USER_PROVIDED,
            )
        ],
        scan_profile="OWASP_API_TOP_10_SAFE",
        authorization_context=AuthorizationContext(
            authorization_confirmed=True,
            credentials_available=False,
        ),
        authentication_required_endpoints=[
            "/api/v1/admin"
        ],
    )


def mock_response(status_code):
    response = MagicMock()
    response.status_code = status_code
    response.headers = {
        "Content-Type": "application/json"
    }
    response.url = "http://localhost:8888/api/v1/admin"
    return response


@patch(
    "security_engine.request_client.SafeRequestClient"
)
def test_successful_anonymous_access_is_potential_exposure(
    mock_client_class,
    scan_input,
):
    client = mock_client_class.return_value
    client.request.return_value = mock_response(200)

    coverage, findings, evidence = (
        API5BrokenFunctionAuthorizationDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert len(findings) == 1
    assert len(evidence) == 1
    assert findings[0].status == CheckStatus.INCONCLUSIVE
    assert findings[0].evidence_id == evidence[0].evidence_id
    assert evidence[0].finding_id == findings[0].id


@patch(
    "security_engine.request_client.SafeRequestClient"
)
def test_forbidden_response(
    mock_client_class,
    scan_input,
):
    client = mock_client_class.return_value
    client.request.return_value = mock_response(403)

    coverage, findings, evidence = (
        API5BrokenFunctionAuthorizationDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


@patch(
    "security_engine.request_client.SafeRequestClient"
)
def test_server_error_is_inconclusive(
    mock_client_class,
    scan_input,
):
    client = mock_client_class.return_value
    client.request.return_value = mock_response(500)

    coverage, findings, evidence = (
        API5BrokenFunctionAuthorizationDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_missing_privileged_endpoint_is_inconclusive(scan_input):
    scan_input.authentication_required_endpoints = []

    coverage, findings, evidence = (
        API5BrokenFunctionAuthorizationDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_unconfirmed_authorization_is_inconclusive(scan_input):
    scan_input.authorization_context.authorization_confirmed = False

    coverage, findings, evidence = (
        API5BrokenFunctionAuthorizationDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []
