import pytest

from fastapi.testclient import TestClient

from backend.main import app
from backend.api.reports import _report_store
from backend.services.scan_service import _scans
from backend.services.report_service import generate_vapt_report


client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_report_data():
    """Clear test data before and after each test."""
    _report_store.clear()

    test_scan_ids = [
        "test-queued-scan",
        "test-completed-scan",
        "real-pdf-test-scan",
    ]

    for scan_id in test_scan_ids:
        _scans.pop(scan_id, None)

    yield

    _report_store.clear()

    for scan_id in test_scan_ids:
        _scans.pop(scan_id, None)


def test_report_generation_for_unknown_scan():
    response = client.post("/api/reports/invalid-scan-id")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found."


def test_report_generation_for_incomplete_scan():
    scan_id = "test-queued-scan"

    _scans[scan_id] = {
        "scan_id": scan_id,
        "status": "QUEUED",
        "target_id": "test-target",
    }

    response = client.post(f"/api/reports/{scan_id}")

    assert response.status_code == 400
    assert "completed scan" in response.json()["detail"].lower()


def test_pdf_download_before_generation():
    response = client.get(
        "/api/reports/nonexistent-scan/download"
    )

    assert response.status_code == 404


def test_report_service_rejects_unknown_scan():
    with pytest.raises(ValueError, match="Scan not found"):
        generate_vapt_report("unknown-scan")


def test_report_download_returns_pdf(monkeypatch):
    scan_id = "test-completed-scan"

    _scans[scan_id] = {
        "scan_id": scan_id,
        "status": "COMPLETED",
        "target_id": None,
    }

    # Controlled PDF fixture for testing the API download flow.
    test_pdf = b"%PDF-1.4\nAccessLens test PDF\n%%EOF"

    monkeypatch.setattr(
        "backend.api.reports.generate_vapt_report",
        lambda requested_scan_id: test_pdf,
    )

    create_response = client.post(
        f"/api/reports/{scan_id}"
    )

    assert create_response.status_code == 200

    response_data = create_response.json()

    assert response_data["scan_id"] == scan_id
    assert response_data["file_size_bytes"] == len(test_pdf)

    download_response = client.get(
        f"/api/reports/{scan_id}/download"
    )

    assert download_response.status_code == 200
    assert download_response.headers["content-type"] == "application/pdf"
    assert download_response.content.startswith(b"%PDF")
    assert download_response.content == test_pdf


def test_real_vapt_pdf_generation():
    """Verify that ReportLab generates a genuine PDF."""

    scan_id = "real-pdf-test-scan"

    _scans[scan_id] = {
        "scan_id": scan_id,
        "status": "COMPLETED",
        "target_id": None,
    }

    pdf_bytes = generate_vapt_report(scan_id)

    # Verify PDF signature.
    assert pdf_bytes.startswith(b"%PDF")

    # Verify generated document is not empty.
    assert len(pdf_bytes) > 1000

    # Verify PDF structure.
    assert b"/Type /Page" in pdf_bytes
    assert b"%%EOF" in pdf_bytes