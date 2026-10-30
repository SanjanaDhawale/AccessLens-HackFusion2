
from security_engine.detectors.api9_inventory_management import (
    API9InventoryManagementDetector,
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
            ),
            Endpoint(
                path="/api/users",
                method="GET",
                source="AUTHORIZED_DISCOVERY",
            ),
        ]

    return ScanInput(
        scan_id="test-api9",
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


def test_matching_inventories_pass_comparison():
    coverage, findings, evidence = (
        API9InventoryManagementDetector().run(make_scan_input())
    )

    assert coverage["status"] == CheckStatus.PASS
    assert findings == []
    assert evidence == []


def test_undocumented_discovered_endpoint_is_reported():
    endpoints = [
        Endpoint(
            path="/api/users",
            method="GET",
            source="OPENAPI",
        ),
        Endpoint(
            path="/api/users",
            method="GET",
            source="AUTHORIZED_DISCOVERY",
        ),
        Endpoint(
            path="/api/admin",
            method="GET",
            source="AUTHORIZED_DISCOVERY",
        ),
    ]

    coverage, findings, evidence = (
        API9InventoryManagementDetector().run(
            make_scan_input(endpoints=endpoints)
        )
    )

    assert coverage["status"] == CheckStatus.INCONCLUSIVE
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.INCONCLUSIVE
    assert len(evidence) == 1


def test_missing_discovery_inventory_is_inconclusive():
    endpoints = [
        Endpoint(
            path="/api/users",
            method="GET",
            source="OPENAPI",
        )
    ]

    coverage, findings, evidence = (
        API9InventoryManagementDetector().run(
            make_scan_input(endpoints=endpoints)
        )
    )

    assert coverage["status"] == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_unconfirmed_authorization_is_inconclusive():
    coverage, findings, evidence = (
        API9InventoryManagementDetector().run(
            make_scan_input(authorization=False)
        )
    )

    assert coverage["status"] == CheckStatus.INCONCLUSIVE
    assert findings == []
    assert evidence == []


def test_finding_and_evidence_ids_match():
    endpoints = [
        Endpoint(
            path="/api/users",
            method="GET",
            source="OPENAPI",
        ),
        Endpoint(
            path="/api/admin",
            method="GET",
            source="AUTHORIZED_DISCOVERY",
        ),
    ]

    coverage, findings, evidence = (
        API9InventoryManagementDetector().run(
            make_scan_input(endpoints=endpoints)
        )
    )

    assert findings[0].id == evidence[0].finding_id
    assert findings[0].evidence_id == evidence[0].evidence_id
