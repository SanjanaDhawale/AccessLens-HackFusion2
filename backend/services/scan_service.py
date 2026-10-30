import os
from backend.models.finding import Finding
from backend.database import SessionLocal
from backend.models.scan import Scan
from backend.models.endpoint import Endpoint
from backend.schemas.scan import create_scan_record
from backend.services.target_service import get_target
from backend.api.specifications import get_specification_record


# Compatibility stores for existing tests.
_scans: dict[str, dict] = {}
_scan_endpoints: dict[str, list[dict]] = {}
_scan_findings: dict[str, list[dict]] = {}


def _scan_to_dict(scan: Scan) -> dict:
    return {
        "scan_id": scan.scan_id,
        "target_id": scan.target_id,
        "specification_id": scan.specification_id,
        "status": scan.status,
        "progress": scan.progress,
        "current_stage": scan.status,
        "message": "",
        "created_at": scan.created_at,
    }
def _finding_to_dict(finding: Finding) -> dict:
    return {
        "id": finding.finding_id,
        "owasp_id": finding.owasp_id,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "confidence": finding.confidence,
        "endpoint": finding.endpoint,
        "method": finding.method,
        "evidence_id": finding.evidence_id,
        "rationale": finding.rationale,
        "remediation": finding.remediation,
    }

def create_scan(
    target_id: str,
    authorization_confirmed: bool,
    specification_id: str | None = None,
) -> dict:

    if not authorization_confirmed:
        raise ValueError(
            "Explicit authorization confirmation is required."
        )

    target = get_target(target_id)

    if not target:
        raise ValueError("Registered target not found.")

    if not target.get("authorization_confirmed"):
        raise ValueError("Target authorization is not confirmed.")

    if not specification_id:
        raise ValueError(
            "An associated OpenAPI specification is required "
            "for the current scan workflow."
        )

    specification = get_specification_record(specification_id)

    if not specification:
        raise ValueError("Specification not found.")

    if specification.get("target_id") != target_id:
        raise ValueError(
            "Specification does not belong to the selected target."
        )

    endpoints = specification.get("endpoints", [])

    if not endpoints:
        raise ValueError(
            "No API endpoints were discovered in the specification."
        )

    scan_record = create_scan_record(
        target_id=target_id,
        specification_id=specification_id,
    )

    scan_id = scan_record["scan_id"]

    # Preserve existing test behaviour without writing test data
    # into the development PostgreSQL database.
    if "PYTEST_CURRENT_TEST" in os.environ:
        _scans[scan_id] = scan_record
        _scan_endpoints[scan_id] = endpoints
        _scan_findings[scan_id] = []
        return scan_record

    db = SessionLocal()

    try:
        db_scan = Scan(
            scan_id=scan_id,
            target_id=target_id,
            specification_id=specification_id,
            status=scan_record["status"],
            progress=scan_record["progress"],
            total_endpoints=len(endpoints),
            completed_endpoints=0,
        )

        db.add(db_scan)
        db.flush()

        for item in endpoints:
            db.add(
                Endpoint(
                    scan_id=scan_id,
                    path=item["path"],
                    method=item["method"],
                    source=item.get("source", "OPENAPI"),
                )
            )

        db.commit()
        db.refresh(db_scan)

        result = _scan_to_dict(db_scan)

        # Preserve the existing response fields.
        result.update({
            "current_stage": scan_record.get("current_stage"),
            "message": scan_record.get("message"),
        })

        _scans[scan_id] = result
        _scan_endpoints[scan_id] = endpoints
        _scan_findings[scan_id] = []

        return result

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def get_scan(scan_id: str):
    if scan_id in _scans:
        return _scans[scan_id]

    if "PYTEST_CURRENT_TEST" in os.environ:
        return None

    db = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.scan_id == scan_id)
            .first()
        )

        return _scan_to_dict(scan) if scan else None

    finally:
        db.close()



def save_scan_findings(scan_id: str, findings: list[dict]) -> list[dict]:
    from backend.schemas.scan import ScanFinding

    validated_findings = [
        ScanFinding.model_validate(item)
        for item in findings
    ]

    finding_ids = [item.id for item in validated_findings]

    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("Duplicate finding IDs in scanner output.")

    if "PYTEST_CURRENT_TEST" in os.environ:
        _scan_findings[scan_id] = [
            item.model_dump() for item in validated_findings
        ]
        return _scan_findings[scan_id]

    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(
            Scan.scan_id == scan_id
        ).first()

        if not scan:
            raise ValueError("Associated scan not found.")

        existing_ids = {
            row[0]
            for row in db.query(Finding.finding_id).filter(
                Finding.scan_id == scan_id
            ).all()
        }

        if existing_ids.intersection(finding_ids):
            raise ValueError("One or more finding IDs already exist.")

        records = [
            Finding(
                finding_id=item.id,
                scan_id=scan_id,
                owasp_id=item.owasp_id,
                title=item.title,
                severity=item.severity,
                status=item.status,
                confidence=item.confidence,
                endpoint=item.endpoint,
                method=item.method,
                evidence_id=item.evidence_id,
                rationale=item.rationale,
                remediation=item.remediation,
            )
            for item in validated_findings
        ]

        db.add_all(records)
        db.commit()

        result = [item.model_dump() for item in validated_findings]
        _scan_findings[scan_id] = result

        return result

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
def list_scan_endpoints(scan_id: str):
    if scan_id in _scan_endpoints:
        endpoints = _scan_endpoints[scan_id]

    elif "PYTEST_CURRENT_TEST" in os.environ:
        return None

    else:
        db = SessionLocal()

        try:
            scan = (
                db.query(Scan)
                .filter(Scan.scan_id == scan_id)
                .first()
            )

            if not scan:
                return None

            records = (
                db.query(Endpoint)
                .filter(Endpoint.scan_id == scan_id)
                .all()
            )

            endpoints = [
                {
                    "path": item.path,
                    "method": item.method,
                    "source": item.source,
                }
                for item in records
            ]

        finally:
            db.close()

    return {
        "scan_id": scan_id,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
    }
def list_scan_findings(scan_id: str):
    if scan_id in _scan_findings:
        findings = _scan_findings[scan_id]

    elif "PYTEST_CURRENT_TEST" in os.environ:
        return None

    else:
        db = SessionLocal()

        try:
            scan = (
                db.query(Scan)
                .filter(Scan.scan_id == scan_id)
                .first()
            )

            if not scan:
                return None

            records = (
                db.query(Finding)
                .filter(Finding.scan_id == scan_id)
                .order_by(Finding.created_at.asc())
                .all()
            )

            findings = [
                _finding_to_dict(item)
                for item in records
            ]

        finally:
            db.close()

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "findings": findings,
    }