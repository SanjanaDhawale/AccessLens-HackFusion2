
import json
from unittest.mock import MagicMock

from security_engine.detectors.api1_bola import API1BOLADetector
from security_engine.models import (
    AuthorizationContext,
    BOLATestCase,
    BOLATestConfig,
    BOLAIdentity,
    BOLAObjectReference,
    CheckStatus,
    Endpoint,
    EndpointSource,
    ScanInput,
)
from security_engine.request_client import SafeResponse


OBJECT_ID = "object-123"
ENDPOINT_PATH = f"/identity/api/v2/vehicle/{OBJECT_ID}/location"


def create_scan_input():
    bola_config = BOLATestConfig(
        identities=[
            BOLAIdentity(
                identity_id="user_a",
                credential_ref="CRAPI_USER_A",
            ),
            BOLAIdentity(
                identity_id="user_b",
                credential_ref="CRAPI_USER_B",
            ),
        ],
        object_reference=BOLAObjectReference(
            object_id=OBJECT_ID,
            object_type="vehicle",
            owner_identity_id="user_a",
            read_path=ENDPOINT_PATH,
        ),
        test_cases=[
            BOLATestCase(
                case_id="owner-access",
                identity_id="user_a",
                access_type="OWNER_ACCESS",
                expected_access="ALLOW",
            ),
            BOLATestCase(
                case_id="cross-account-access",
                identity_id="user_b",
                access_type="CROSS_ACCOUNT_ACCESS",
                expected_access="DENY",
            ),
        ],
    )

    return ScanInput(
        scan_id="test-bola-001",
        target_url="http://localhost:8888",
        authorized_hosts=["localhost"],
        allowed_paths=[ENDPOINT_PATH],
        endpoints=[
            Endpoint(
                path=ENDPOINT_PATH,
                method="GET",
                operation_id="get_vehicle_location",
                source=EndpointSource.USER_PROVIDED,
            )
        ],
        scan_profile="OWASP_API_TOP_10_SAFE",
        authorization_context=AuthorizationContext(
            authorization_confirmed=True,
            credentials_available=True,
        ),
        bola_test=bola_config,
    )


def create_response(status_code, body):
    return SafeResponse(
        status_code=status_code,
        headers={"Content-Type": "application/json"},
        body_excerpt=json.dumps(body),
        url=f"http://localhost:8888{ENDPOINT_PATH}",
    )


def create_mock_client(responses):
    mock_client = MagicMock()

    # Important: SafeRequestClient is used with a "with" statement.
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False

    mock_client.request.side_effect = responses

    return mock_client


def patch_detector(monkeypatch, responses):
    mock_client = create_mock_client(responses)

    monkeypatch.setattr(
        "security_engine.detectors.api1_bola.SafeRequestClient",
        lambda *args, **kwargs: mock_client,
    )

    monkeypatch.setattr(
        "security_engine.detectors.api1_bola.resolve_bearer_token",
        lambda credential_ref: f"mock-token-{credential_ref}",
    )

    return mock_client


# ---------------------------------------------------------
# Test 1: Detect unauthorized cross-account access
# ---------------------------------------------------------

def test_bola_detects_cross_account_access(monkeypatch):
    scan_input = create_scan_input()

    owner_response = create_response(
        200,
        {
            "id": OBJECT_ID,
            "vehicleLocation": "Protected location",
        },
    )

    attacker_response = create_response(
        200,
        {
            "id": OBJECT_ID,
            "vehicleLocation": "Protected location",
        },
    )

    mock_client = patch_detector(
        monkeypatch,
        [owner_response, attacker_response],
    )

    detector = API1BOLADetector()
    evidence = []

    coverage, findings = detector.run(scan_input, evidence)

    assert coverage.status == CheckStatus.FAIL
    assert len(findings) == 1

    finding = findings[0]

    assert finding.owasp_id == "API1:2023"
    assert finding.status == CheckStatus.FAIL
    assert finding.evidence_id is not None
    assert finding.confidence.value == "CONFIRMED"

    assert len(evidence) == 1
    assert evidence[0].finding_id == finding.id
    assert evidence[0].evidence_id == finding.evidence_id

    assert mock_client.request.call_count == 2


# ---------------------------------------------------------
# Test 2: Cross-account access is denied
# ---------------------------------------------------------

def test_bola_passes_when_cross_account_access_is_denied(monkeypatch):
    scan_input = create_scan_input()

    owner_response = create_response(
        200,
        {
            "id": OBJECT_ID,
            "vehicleLocation": "Protected location",
        },
    )

    attacker_response = create_response(
        403,
        {"message": "Forbidden"},
    )

    mock_client = patch_detector(
        monkeypatch,
        [owner_response, attacker_response],
    )

    detector = API1BOLADetector()
    evidence = []

    coverage, findings = detector.run(scan_input, evidence)

    assert coverage.status == CheckStatus.PASS
    assert findings == []
    assert evidence == []

    assert mock_client.request.call_count == 2


# ---------------------------------------------------------
# Test 3: Owner access must succeed first
# ---------------------------------------------------------

def test_bola_is_inconclusive_when_owner_access_fails(monkeypatch):
    scan_input = create_scan_input()

    owner_response = create_response(
        403,
        {"message": "Forbidden"},
    )

    mock_client = patch_detector(
        monkeypatch,
        [owner_response],
    )

    detector = API1BOLADetector()
    evidence = []

    coverage, findings = detector.run(scan_input, evidence)

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []

    # Cross-account request must not be sent.
    assert mock_client.request.call_count == 1


# ---------------------------------------------------------
# Test 4: Invalid owner response is inconclusive
# ---------------------------------------------------------

def test_bola_is_inconclusive_when_owner_response_is_invalid(monkeypatch):
    scan_input = create_scan_input()

    owner_response = create_response(
        200,
        {
            "message": "Unexpected response",
        },
    )

    mock_client = patch_detector(
        monkeypatch,
        [owner_response],
    )

    detector = API1BOLADetector()
    evidence = []

    coverage, findings = detector.run(scan_input, evidence)

    assert coverage.status == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []

    assert mock_client.request.call_count == 1


# ---------------------------------------------------------
# Test 5: Finding and evidence IDs must match
# ---------------------------------------------------------

def test_bola_finding_and_evidence_ids_match(monkeypatch):
    scan_input = create_scan_input()

    owner_response = create_response(
        200,
        {
            "id": OBJECT_ID,
            "vehicleLocation": "Protected location",
        },
    )

    attacker_response = create_response(
        200,
        {
            "id": OBJECT_ID,
            "vehicleLocation": "Protected location",
        },
    )

    patch_detector(
        monkeypatch,
        [owner_response, attacker_response],
    )

    detector = API1BOLADetector()
    evidence = []

    coverage, findings = detector.run(scan_input, evidence)

    assert len(findings) == 1
    assert len(evidence) == 1

    finding = findings[0]
    evidence_item = evidence[0]

    assert finding.evidence_id == evidence_item.evidence_id
    assert finding.id == evidence_item.finding_id
    assert evidence_item.check_id == "API1:2023"
