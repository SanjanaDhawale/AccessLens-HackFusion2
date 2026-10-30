from unittest.mock import MagicMock, patch

from security_engine.detectors.api2_broken_authentication import (
    API2BrokenAuthenticationDetector,
)
from security_engine.models import (
    AuthorizationContext,
    CheckStatus,
    Endpoint,
    EndpointSource,
    ScanInput,
)


def make_scan_input():
    return ScanInput(
        scan_id="api2-test",
        target_url="http://localhost:8888",
        authorized_hosts=["localhost"],
        allowed_paths=["/"],
        endpoints=[
            Endpoint(
                path="/api/protected",
                method="GET",
                source=EndpointSource.USER_PROVIDED,
            )
        ],
        scan_profile="OWASP_API_TOP_10_SAFE",
        authorization_context=AuthorizationContext(
            authorization_confirmed=True,
            credentials_available=True,
        ),
        authentication_required_endpoints=[
            "/api/protected"
        ],
        allow_private_targets=True,
        authorized_ips=["127.0.0.1"],
    )


@patch(
    "security_engine.detectors.api2_broken_authentication.SafeRequestClient"
)
def test_api2_detects_unauthenticated_access(mock_client_class):
    scan_input = make_scan_input()
    evidence = []

    mock_client = MagicMock()
    mock_client.request.return_value = MagicMock(
        status_code=200,
        headers={"content-type": "application/json"},
        body_excerpt='{"message":"ok"}',
        url="http://localhost:8888/api/protected",
    )

    mock_client_class.return_value.__enter__.return_value = mock_client

    coverage, findings = API2BrokenAuthenticationDetector().run(
        scan_input,
        evidence,
    )

    assert coverage.status == CheckStatus.FAIL
    assert len(findings) == 1
    assert findings[0].owasp_id == "API2:2023"
    assert findings[0].status == CheckStatus.FAIL

    assert len(evidence) == 1
    assert evidence[0].finding_id == findings[0].id
    assert evidence[0].request.headers == {}

    # Confirm no authentication header was sent.
    mock_client.request.assert_called_once_with(
        "GET",
        "/api/protected",
    )


@patch(
    "security_engine.detectors.api2_broken_authentication.SafeRequestClient"
)
def test_api2_passes_when_access_is_rejected(mock_client_class):
    scan_input = make_scan_input()
    evidence = []

    mock_client = MagicMock()
    mock_client.request.return_value = MagicMock(
        status_code=401,
        headers={},
        body_excerpt="",
        url="http://localhost:8888/api/protected",
    )

    mock_client_class.return_value.__enter__.return_value = mock_client

    coverage, findings = API2BrokenAuthenticationDetector().run(
        scan_input,
        evidence,
    )

    assert coverage.status == CheckStatus.PASS
    assert findings == []
    assert evidence == []


def test_api2_is_inconclusive_without_protected_endpoints():
    scan_input = make_scan_input()
    scan_input.authentication_required_endpoints = []

    coverage, findings = API2BrokenAuthenticationDetector().run(
        scan_input,
        [],
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []


def test_api2_is_inconclusive_without_authorization():
    scan_input = make_scan_input()
    scan_input.authorization_context.authorization_confirmed = False

    coverage, findings = API2BrokenAuthenticationDetector().run(
        scan_input,
        [],
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []


@patch(
    "security_engine.detectors.api2_broken_authentication.SafeRequestClient"
)
def test_api2_returns_inconclusive_for_server_error(mock_client_class):
    scan_input = make_scan_input()
    evidence = []

    mock_client = MagicMock()
    mock_client.request.return_value = MagicMock(
        status_code=500,
        headers={},
        body_excerpt="",
        url="http://localhost:8888/api/protected",
    )

    mock_client_class.return_value.__enter__.return_value = mock_client

    coverage, findings = API2BrokenAuthenticationDetector().run(
        scan_input,
        evidence,
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []