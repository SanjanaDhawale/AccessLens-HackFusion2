from __future__ import annotations

from security_engine.models import (
    ScanInput,
    ScanOutput,
    ScanStatus,
    CheckStatus,
    Coverage,
    Evidence,
    Summary,
    model_to_dict,
)
from security_engine.scope_validator import validate_scan_scope
from security_engine.detectors.api1_bola import API1BOLADetector
from security_engine.detectors.api8_misconfiguration import (
    API8MisconfigurationDetector,
)

OWASP_API_TOP_10_2023 = [
    ("API1:2023", "Broken Object Level Authorization"),
    ("API2:2023", "Broken Authentication"),
    ("API3:2023", "Broken Object Property Level Authorization"),
    ("API4:2023", "Unrestricted Resource Consumption"),
    ("API5:2023", "Broken Function Level Authorization"),
    ("API6:2023", "Unrestricted Access to Sensitive Business Flows"),
    ("API7:2023", "Server Side Request Forgery"),
    ("API8:2023", "Security Misconfiguration"),
    ("API9:2023", "Improper Inventory Management"),
    ("API10:2023", "Unsafe Consumption of APIs"),
]


def _validate_evidence_integrity(findings, evidence) -> None:
    """Fail closed if evidence IDs or finding/evidence links are invalid."""
    finding_ids = [finding.id for finding in findings]
    evidence_ids = [item.evidence_id for item in evidence]

    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("Duplicate finding IDs detected.")
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("Duplicate evidence IDs detected.")

    evidence_by_id = {item.evidence_id: item for item in evidence}
    finding_id_set = set(finding_ids)

    for finding in findings:
        linked = evidence_by_id.get(finding.evidence_id)
        if linked is None or linked.finding_id != finding.id:
            raise ValueError("Finding evidence reference is invalid.")

    for item in evidence:
        if item.finding_id not in finding_id_set:
            raise ValueError("Evidence references an unknown finding.")


def run_security_scan(scan_input: dict) -> dict:
    """Run authorized checks and return a stable, JSON-compatible contract."""
    try:
        validated_input = ScanInput.model_validate(scan_input)
        validate_scan_scope(validated_input)

        evidence: list[Evidence] = []
        findings = []
        detector_coverage = {}

        detectors = [API1BOLADetector(), API8MisconfigurationDetector()]
        for detector in detectors:
            coverage_item, detector_findings = detector.run(validated_input, evidence)
            detector_coverage[coverage_item.owasp_id] = coverage_item
            findings.extend(detector_findings)

        # Always return all ten OWASP categories. Unimplemented categories are
        # explicitly INCONCLUSIVE; they are never silently reported as PASS.
        coverage = []
        for owasp_id, category in OWASP_API_TOP_10_2023:
            coverage.append(
                detector_coverage.get(
                    owasp_id,
                    Coverage(
                        owasp_id=owasp_id,
                        category=category,
                        status=CheckStatus.INCONCLUSIVE,
                        reason="Detector is not implemented in this MVP; this category was not tested.",
                    ),
                )
            )

        _validate_evidence_integrity(findings, evidence)

        summary = Summary(
            tested=len(coverage),
            passed=sum(item.status == CheckStatus.PASS for item in coverage),
            failed=sum(item.status == CheckStatus.FAIL for item in coverage),
            inconclusive=sum(item.status == CheckStatus.INCONCLUSIVE for item in coverage),
            not_applicable=sum(item.status == CheckStatus.NOT_APPLICABLE for item in coverage),
        )

        output = ScanOutput(
            scan_id=validated_input.scan_id,
            status=ScanStatus.COMPLETED,
            coverage=coverage,
            findings=findings,
            evidence=evidence,
            summary=summary,
        )
        return model_to_dict(output)

    except Exception:
        failed_coverage = [
            {
                "owasp_id": owasp_id,
                "category": category,
                "status": CheckStatus.INCONCLUSIVE.value,
                "reason": "Scan failed before this category could be tested.",
            }
            for owasp_id, category in OWASP_API_TOP_10_2023
        ]
        return {
            "scan_id": scan_input.get("scan_id", "unknown") if isinstance(scan_input, dict) else "unknown",
            "status": ScanStatus.FAILED.value,
            "coverage": failed_coverage,
            "findings": [],
            "evidence": [],
            "summary": {"tested": 10, "passed": 0, "failed": 0, "inconclusive": 10, "not_applicable": 0},
            "error": "Scan could not be completed. Verify the input, authorization, scope, and target availability.",
            "error_code": "SCAN_FAILED",
        }
