
from security_engine.engine import run_security_scan


def make_scan_input():
    return {
        "scan_id": "integration-test-001",
        "target_url": "http://localhost:8888",
        "authorized_hosts": ["localhost"],
        "allowed_paths": ["/"],
        "endpoints": [],
        "scan_profile": "OWASP_API_TOP_10_SAFE",
        "authorization_context": {
            "authorization_confirmed": True,
            "credentials_available": False,
        },

        # Explicit authorization for the local crAPI lab.
        "allow_private_targets": True,
        "authorized_ips": [
            "127.0.0.1",
            "::1",
        ],
    }


def test_engine_returns_all_ten_owasp_categories():
    result = run_security_scan(make_scan_input())

    assert result["status"] == "COMPLETED"

    expected_categories = {
        "API1:2023",
        "API2:2023",
        "API3:2023",
        "API4:2023",
        "API5:2023",
        "API6:2023",
        "API7:2023",
        "API8:2023",
        "API9:2023",
        "API10:2023",
    }

    actual_categories = {
        item["owasp_id"]
        for item in result["coverage"]
    }

    assert actual_categories == expected_categories
    assert len(result["coverage"]) == 10

    assert (
        result["summary"]["tested"]
        == 10
    )


def test_engine_does_not_report_unimplemented_checks_as_pass():
    result = run_security_scan(make_scan_input())

    assert result["status"] == "COMPLETED"

    for item in result["coverage"]:
        assert item["status"] in {
            "PASS",
            "FAIL",
            "INCONCLUSIVE",
            "NOT_APPLICABLE",
        }

        # Empty endpoint configuration must not automatically
        # make every OWASP category PASS.
        if item["status"] == "INCONCLUSIVE":
            assert item["reason"]
