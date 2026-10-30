from security_engine.engine import run_security_scan


def test_invalid_scan_returns_stable_failed_contract_without_exception_details():
    result = run_security_scan({"scan_id": "contract-test"})

    assert result["scan_id"] == "contract-test"
    assert result["status"] == "FAILED"
    assert len(result["coverage"]) == 10
    assert all(item["status"] == "INCONCLUSIVE" for item in result["coverage"])
    assert result["findings"] == []
    assert result["evidence"] == []
    assert result["summary"] == {
        "tested": 10,
        "passed": 0,
        "failed": 0,
        "inconclusive": 10,
        "not_applicable": 0,
    }
    assert result["error_code"] == "SCAN_FAILED"
    assert "Field required" not in result["error"]


def test_completed_scan_always_contains_all_ten_categories(monkeypatch):
    from security_engine import engine
    from security_engine.models import CheckStatus, Coverage

    class FakeDetector:
        def __init__(self, owasp_id, category):
            self.owasp_id = owasp_id
            self.category = category

        def run(self, scan_input, evidence):
            return Coverage(
                owasp_id=self.owasp_id,
                category=self.category,
                status=CheckStatus.PASS,
                reason="Mocked test passed.",
            ), []

    monkeypatch.setattr(engine, "API1BOLADetector", lambda: FakeDetector("API1:2023", "BOLA"))
    monkeypatch.setattr(engine, "API8MisconfigurationDetector", lambda: FakeDetector("API8:2023", "Misconfiguration"))
    monkeypatch.setattr(engine, "validate_scan_scope", lambda value: None)

    payload = {
        "scan_id": "coverage-contract-test",
        "target_url": "http://example.test",
        "authorized_hosts": ["example.test"],
        "allowed_paths": ["/api"],
        "endpoints": [],
        "scan_profile": "OWASP_API_TOP_10_SAFE",
        "authorization_context": {"authorization_confirmed": True, "credentials_available": False},
    }
    result = engine.run_security_scan(payload)

    assert result["status"] == "COMPLETED"
    assert len(result["coverage"]) == 10
    assert result["summary"]["tested"] == 10
    assert result["summary"]["inconclusive"] == 8
    assert all(
        item["status"] == "INCONCLUSIVE"
        for item in result["coverage"]
        if item["owasp_id"] not in {"API1:2023", "API8:2023"}
    )


def test_evidence_integrity_rejects_missing_reference():
    import pytest
    from types import SimpleNamespace
    from security_engine.engine import _validate_evidence_integrity

    finding = SimpleNamespace(id="F-1", evidence_id="E-MISSING")
    with pytest.raises(ValueError, match="evidence reference"):
        _validate_evidence_integrity([finding], [])


def test_evidence_integrity_rejects_duplicate_evidence_ids():
    import pytest
    from types import SimpleNamespace
    from security_engine.engine import _validate_evidence_integrity

    evidence = [
        SimpleNamespace(evidence_id="E-1", finding_id="F-1"),
        SimpleNamespace(evidence_id="E-1", finding_id="F-1"),
    ]
    finding = SimpleNamespace(id="F-1", evidence_id="E-1")
    with pytest.raises(ValueError, match="Duplicate evidence IDs"):
        _validate_evidence_integrity([finding], evidence)
