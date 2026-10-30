
from security_engine.detectors.api7_ssrf import API7SSRFDetector
from security_engine.models import (
    AuthorizationContext,
    CheckStatus,
    Endpoint,
    ScanInput,
)


def make_scan_input(authorization_confirmed=True, endpoints=None):
    if endpoints is None:
        endpoints = [
            Endpoint(
                path="/api/items",
                method="GET",
                source="OPENAPI",
            )
        ]

    return ScanInput(
        scan_id="test-api7",
        target_url="http://localhost:8888",
        authorized_hosts=["localhost"],
        allowed_paths=["/"],
        endpoints=endpoints,
        scan_profile="OWASP_API_TOP_10_SAFE",
        authorization_context=AuthorizationContext(
            authorization_confirmed=authorization_confirmed,
            credentials_available=False,
        ),
    )


def test_ssrf_assessment_is_inconclusive_without_active_testing():
    detector = API7SSRFDetector()

    coverage, findings, evidence = detector.run(make_scan_input())

    assert coverage["status"] == CheckStatus.INCONCLUSIVE
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.INCONCLUSIVE
    assert len(evidence) == 1


def test_unconfirmed_authorization_skips_assessment():
    detector = API7SSRFDetector()

    coverage, findings, evidence = detector.run(
        make_scan_input(authorization_confirmed=False)
    )

    assert coverage["status"] == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_no_endpoints_returns_inconclusive():
    detector = API7SSRFDetector()

    coverage, findings, evidence = detector.run(
        make_scan_input(endpoints=[])
    )

    assert coverage["status"] == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_finding_and_evidence_ids_match():
    detector = API7SSRFDetector()

    coverage, findings, evidence = detector.run(make_scan_input())

    assert len(findings) == 1
    assert len(evidence) == 1
    assert findings[0].id == evidence[0].finding_id
    assert findings[0].evidence_id == evidence[0].evidence_id


def test_detector_does_not_send_network_requests():
    detector = API7SSRFDetector()

    coverage, findings, evidence = detector.run(make_scan_input())

    assert coverage["status"] == CheckStatus.INCONCLUSIVE
    assert evidence[0].response.status_code is None
    assert "No network request" in evidence[0].notes
