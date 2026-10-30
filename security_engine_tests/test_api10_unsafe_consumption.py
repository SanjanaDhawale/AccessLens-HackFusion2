
from security_engine.detectors.api10_unsafe_consumption import (
    API10UnsafeConsumptionDetector,
)

from security_engine.models import (
    AuthorizationContext,
    CheckStatus,
    Endpoint,
    ScanInput,
)


def make_scan_input(authorization=True, endpoints=None):
    if endpoints is None:
        endpoints = [
            Endpoint(
                path="/api/users",
                method="GET",
                source="OPENAPI",
            )
        ]

    return ScanInput(
        scan_id="test-api10",
        target_url="http://localhost:8888",
        authorized_hosts=["localhost"],
        allowed_paths=["/"],
        endpoints=endpoints,
        scan_profile="OWASP_API_TOP_10_SAFE",
        authorization_context=AuthorizationContext(
            authorization_confirmed=authorization,
            credentials_available=False,
        ),
    )


def test_api10_without_dependency_context_is_inconclusive():
    coverage, findings, evidence = (
        API10UnsafeConsumptionDetector().run(make_scan_input())
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert "downstream" in coverage.reason.lower()
    assert findings == []
    assert evidence == []


def test_unconfirmed_authorization_is_inconclusive():
    coverage, findings, evidence = (
        API10UnsafeConsumptionDetector().run(
            make_scan_input(authorization=False)
        )
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_no_endpoints_is_inconclusive():
    coverage, findings, evidence = (
        API10UnsafeConsumptionDetector().run(
            make_scan_input(endpoints=[])
        )
    )

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_detector_does_not_create_fake_findings():
    coverage, findings, evidence = (
        API10UnsafeConsumptionDetector().run(make_scan_input())
    )

    assert findings == []
    assert evidence == []
    assert coverage.status != CheckStatus.FAIL


def test_detector_returns_three_values():
    result = API10UnsafeConsumptionDetector().run(make_scan_input())

    assert len(result) == 3
    assert isinstance(result[1], list)
    assert isinstance(result[2], list)
