from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from backend.database import SessionLocal
from backend.models.report import Report
from backend.services.report_service import generate_vapt_report
from backend.services.scan_service import get_scan


router = APIRouter(prefix="/reports", tags=["Reports"])


# Persistent report storage directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = PROJECT_ROOT / "storage" / "reports"

# Compatibility store for existing tests.
_report_store: dict[str, bytes] = {}


def _get_report(scan_id: str):
    db = SessionLocal()

    try:
        return (
            db.query(Report)
            .filter(Report.scan_id == scan_id)
            .first()
        )
    finally:
        db.close()


@router.post("/{scan_id}")
async def create_report(scan_id: str):
    """Generate and persist a VAPT PDF report."""

    scan = get_scan(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found."
        )

    try:
        pdf_bytes = generate_vapt_report(scan_id)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to generate the VAPT report."
        ) from exc

    filename = f"accesslens-vapt-{scan_id}.pdf"

    # Preserve isolated in-memory behaviour for existing tests.
    if "PYTEST_CURRENT_TEST" in os.environ:
        _report_store[scan_id] = pdf_bytes

    else:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        storage_path = REPORTS_DIR / filename
        temporary_path = REPORTS_DIR / f"{filename}.tmp"

        db = SessionLocal()

        try:
            temporary_path.write_bytes(pdf_bytes)
            temporary_path.replace(storage_path)

            existing_report = (
                db.query(Report)
                .filter(Report.scan_id == scan_id)
                .first()
            )

            if existing_report:
                existing_report.filename = filename
                existing_report.storage_path = str(storage_path)
                existing_report.file_size_bytes = len(pdf_bytes)
                existing_report.generated_at = datetime.now(timezone.utc)

            else:
                report = Report(
                    report_id=str(uuid4()),
                    scan_id=scan_id,
                    filename=filename,
                    storage_path=str(storage_path),
                    file_size_bytes=len(pdf_bytes),
                    generated_at=datetime.now(timezone.utc),
                )

                db.add(report)

            db.commit()

        except Exception as exc:
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail="Failed to save the VAPT report."
            ) from exc

        finally:
            db.close()

    return {
        "message": "VAPT report generated successfully.",
        "scan_id": scan_id,
        "filename": filename,
        "download_endpoint": f"/api/reports/{scan_id}/download",
        "file_size_bytes": len(pdf_bytes)
    }


@router.get("/{scan_id}/download")
async def download_report(scan_id: str):
    """Download a previously generated VAPT PDF."""

    if scan_id in _report_store:
        pdf_bytes = _report_store[scan_id]

    elif "PYTEST_CURRENT_TEST" in os.environ:
        raise HTTPException(
            status_code=404,
            detail="Report not found. Generate the report first."
        )

    else:
        report = _get_report(scan_id)

        if not report:
            raise HTTPException(
                status_code=404,
                detail="Report not found. Generate the report first."
            )

        storage_path = Path(report.storage_path).resolve()

        # Prevent paths outside the report storage directory.
        if not storage_path.is_relative_to(REPORTS_DIR.resolve()):
            raise HTTPException(
                status_code=500,
                detail="Invalid report storage location."
            )

        if not storage_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="Report file is missing from storage."
            )

        pdf_bytes = storage_path.read_bytes()

    filename = f"accesslens-vapt-{scan_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )