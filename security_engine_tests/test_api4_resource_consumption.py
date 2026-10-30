
from unittest.mock import MagicMock, patch

import pytest

from security_engine.detectors.api4_resource_consumption import (
    API4ResourceConsumptionDetector,
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
        scan_id="api4-test",
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
            credentials_available=False,
        ),
    )


def mock_response(status_code=200, headers=None):
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.url = "http://localhost:8888/api/v1/profile"
    return response


@patch(
    "security_engine.detectors.api4_resource_consumption.SafeRequestClient"
)
def test_rate_limit_metadata_is_informational(
    mock_client_class,
    scan_input,
):
    client = mock_client_class.return_value
    client.request.return_value = mock_response(
        headers={"X-RateLimit-Limit": "100"}
    )

    coverage, findings, evidence = (
        API4ResourceConsumptionDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert len(findings) == 1
    assert len(evidence) == 1
    assert findings[0].status == CheckStatus.INCONCLUSIVE
    assert findings[0].evidence_id == evidence[0].evidence_id


@patch(
    "security_engine.detectors.api4_resource_consumption.SafeRequestClient"
)
def test_missing_rate_limit_metadata_is_not_a_confirmed_vulnerability(
    mock_client_class,
    scan_input,
):
    client = mock_client_class.return_value
    client.request.return_value = mock_response()

    coverage, findings, evidence = (
        API4ResourceConsumptionDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


@patch(
    "security_engine.detectors.api4_resource_consumption.SafeRequestClient"
)
def test_unsuccessful_response_is_inconclusive(
    mock_client_class,
    scan_input,
):
    client = mock_client_class.return_value
    client.request.return_value = mock_response(status_code=500)

    coverage, findings, evidence = (
        API4ResourceConsumptionDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_no_authorized_get_endpoint_is_inconclusive(scan_input):
    scan_input.allowed_paths = []

    coverage, findings, evidence = (
        API4ResourceConsumptionDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_unconfirmed_authorization_is_inconclusive(scan_input):
    scan_input.authorization_context.authorization_confirmed = False

    coverage, findings, evidence = (
        API4ResourceConsumptionDetector().run(scan_input)
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []
