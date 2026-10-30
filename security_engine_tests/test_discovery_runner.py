
from security_engine.discovery_runner import run_discovered_security_scan


def test_discovery_runner_passes_discovered_endpoints(
    monkeypatch,
):
    from security_engine import discovery_runner

    captured = {}

    class FakeEndpoint:
        def model_dump(self, mode="python"):
            return {
                "path": "/identity/api/auth/login",
                "method": "POST",
                "operation_id": "LOGIN",
                "source": "AUTHORIZED_DISCOVERY",
            }

    def fake_discover_endpoints(
        scan_input, route_definitions, method_map
    ):
        return [FakeEndpoint()]

    def fake_run_security_scan(scan_input):
        captured.update(scan_input)
        return {"status": "COMPLETED"}

    monkeypatch.setattr(
        discovery_runner,
        "discover_endpoints",
        fake_discover_endpoints,
    )
    monkeypatch.setattr(
        discovery_runner,
        "run_security_scan",
        fake_run_security_scan,
    )

    scan_input = {
        "scan_id": "test-scan",
        "target_url": "http://localhost:8888",
        "authorized_hosts": ["localhost"],
        "authorized_ips": ["127.0.0.1", "::1"],
        "allow_private_targets": True,
        "allowed_paths": ["/"],
        "endpoints": [],
        "scan_profile": "OWASP_API_TOP_10_SAFE",
        "authorization_context": {
            "authorization_confirmed": True,
            "credentials_available": False,
        },
    }

    result = run_discovered_security_scan(
        scan_input,
        {
            "LOGIN": {
                "service": "identity",
                "path": "api/auth/login",
            }
        },
        {"LOGIN": "POST"},
    )

    assert result["status"] == "COMPLETED"
    assert captured["endpoints"][0]["path"] == (
        "/identity/api/auth/login"
    )
    assert captured["endpoints"][0]["method"] == "POST"
