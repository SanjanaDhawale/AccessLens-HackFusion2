
from unittest.mock import MagicMock, patch

from security_engine.models import CheckStatus, ScanInput
from security_engine.request_client import SafeResponse
from security_engine.detectors.api8_misconfiguration import (
    API8MisconfigurationDetector,
)


def make_scan_input(endpoints=None):
    # Use the default endpoint only when endpoints is None.
    # An explicitly empty list must remain empty.
    if endpoints is None:
        endpoints = [
            {
                "path": "/identity/api/test",
                "method": "GET",
                "source": "USER_PROVIDED",
            }
        ]

    data = {
        "scan_id": "test-api8",
        "target_url": "http://localhost:8888",
        "authorized_hosts": ["localhost"],
        "allowed_paths": ["/identity/api/"],
        "endpoints": endpoints,
        "scan_profile": "OWASP_API_TOP_10_SAFE",
        "authorization_context": {
            "authorization_confirmed": True,
            "credentials_available": False,
        },
    }

    return ScanInput.model_validate(data)


def mocked_client(response):
    """Create a mocked HTTP client without network access."""

    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None
    client.request.return_value = response

    return client


def test_api8_detects_wildcard_cors_with_credentials():
    scan = make_scan_input()
    evidence = []

    response = SafeResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        body_excerpt="",
        url="http://localhost:8888/identity/api/test",
    )

    with patch(
        "security_engine.detectors.api8_misconfiguration.SafeRequestClient",
        return_value=mocked_client(response),
    ):
        coverage, findings = API8MisconfigurationDetector().run(
            scan, evidence
        )

    assert coverage.status == CheckStatus.FAIL
    assert len(findings) == 1
    assert findings[0].evidence_id == evidence[0].evidence_id


def test_api8_does_not_report_safe_cors_headers():
    scan = make_scan_input()
    evidence = []

    response = SafeResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Credentials": "true",
        },
        body_excerpt="",
        url="http://localhost:8888/identity/api/test",
    )

    with patch(
        "security_engine.detectors.api8_misconfiguration.SafeRequestClient",
        return_value=mocked_client(response),
    ):
        coverage, findings = API8MisconfigurationDetector().run(
            scan, evidence
        )

    assert coverage.status == CheckStatus.PASS
    assert findings == []


def test_api8_without_endpoints_is_inconclusive():
    scan = make_scan_input(endpoints=[])
    evidence = []

    coverage, findings = API8MisconfigurationDetector().run(
        scan, evidence
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []


def test_api8_finding_has_evidence_reference():
    scan = make_scan_input()
    evidence = []

    response = SafeResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        body_excerpt="",
        url="http://localhost:8888/identity/api/test",
    )

    with patch(
        "security_engine.detectors.api8_misconfiguration.SafeRequestClient",
        return_value=mocked_client(response),
    ):
        coverage, findings = API8MisconfigurationDetector().run(
            scan, evidence
        )

    assert findings
    assert findings[0].status == CheckStatus.FAIL
    assert findings[0].evidence_id

    assert any(
        item.evidence_id == findings[0].evidence_id
        for item in evidence
    )
