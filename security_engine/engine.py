
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

# API1 and API2
from security_engine.detectors.api1_bola import API1BOLADetector
from security_engine.detectors.api2_broken_authentication import (
    API2BrokenAuthenticationDetector,
)

# API3 to API7
from security_engine.detectors.api3_broken_object_property import (
    API3BrokenObjectPropertyDetector,
)
from security_engine.detectors.api4_resource_consumption import (
    API4ResourceConsumptionDetector,
)
from security_engine.detectors.api5_broken_function_authorization import (
    API5BrokenFunctionAuthorizationDetector,
)
from security_engine.detectors.api6_sensitive_business_flows import (
    API6SensitiveBusinessFlowsDetector,
)
from security_engine.detectors.api7_ssrf import API7SSRFDetector

# API8 to API10
from security_engine.detectors.api8_misconfiguration import (
    API8MisconfigurationDetector,
)
from security_engine.detectors.api9_inventory_management import (
    API9InventoryManagementDetector,
)
from security_engine.detectors.api10_unsafe_consumption import (
    API10UnsafeConsumptionDetector,
)


# ============================================================
# OWASP API SECURITY TOP 10 - 2023
# ============================================================

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


# ============================================================
# OWASP ID NORMALIZATION
# ============================================================

def _canonical_owasp_id(owasp_id: str) -> str:
    """
    Convert short detector IDs such as API10 into API10:2023.

    IDs already containing the year are preserved.
    """

    if not isinstance(owasp_id, str):
        raise TypeError("OWASP ID must be a string.")

    normalized = owasp_id.strip().upper()

    if normalized.startswith("API") and ":" not in normalized:
        suffix = normalized[3:]

        if suffix.isdigit():
            normalized = f"{normalized}:2023"

    return normalized


# ============================================================
# EVIDENCE INTEGRITY VALIDATION
# ============================================================

def _validate_evidence_integrity(findings, evidence) -> None:
    """Validate unique IDs and finding/evidence relationships."""

    finding_ids = [finding.id for finding in findings]
    evidence_ids = [item.evidence_id for item in evidence]

    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("Duplicate finding IDs detected.")

    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("Duplicate evidence IDs detected.")

    evidence_by_id = {
        item.evidence_id: item for item in evidence
    }

    finding_id_set = set(finding_ids)

    for finding in findings:
        linked = evidence_by_id.get(finding.evidence_id)

        if linked is None or linked.finding_id != finding.id:
            raise ValueError(
                "Finding evidence reference is invalid."
            )

    for item in evidence:
        if item.finding_id not in finding_id_set:
            raise ValueError(
                "Evidence references an unknown finding."
            )


# ============================================================
# COVERAGE NORMALIZATION
# ============================================================

def _normalize_coverage(coverage_item, detector):
    """
    Normalize detector coverage to the shared Coverage model.

    Supports:
        1. Coverage model
        2. Dictionary coverage

    Also normalizes API10 to API10:2023.
    """

    detector_id = getattr(
        detector,
        "owasp_id",
        "",
    ) or getattr(
        detector,
        "OWASP_ID",
        "",
    )

    detector_id = (
        _canonical_owasp_id(detector_id)
        if detector_id
        else ""
    )

    if isinstance(coverage_item, Coverage):

        canonical_id = _canonical_owasp_id(
            coverage_item.owasp_id
        )

        if canonical_id == coverage_item.owasp_id:
            return coverage_item

        return Coverage(
            owasp_id=canonical_id,
            category=coverage_item.category,
            status=coverage_item.status,
            reason=coverage_item.reason,
        )

    if isinstance(coverage_item, dict):

        raw_id = coverage_item.get(
            "owasp_id",
            detector_id,
        )

        canonical_id = _canonical_owasp_id(raw_id)

        status = coverage_item.get(
            "status",
            CheckStatus.INCONCLUSIVE,
        )

        if isinstance(status, str):
            status = CheckStatus(status)

        return Coverage(
            owasp_id=canonical_id,
            category=coverage_item.get(
                "category",
                getattr(detector, "category", "Unknown"),
            ),
            status=status,
            reason=coverage_item.get(
                "reason",
                coverage_item.get(
                    "details",
                    "Detector did not provide a reason.",
                ),
            ),
        )

    raise TypeError(
        "Detector returned an unsupported coverage format."
    )


# ============================================================
# DETECTOR EXECUTION
# ============================================================

def _execute_detector(
    detector,
    scan_input,
    shared_evidence,
    uses_shared_evidence,
):
    """
    Execute detectors using their existing interfaces.

    Two-value detectors:
        run(scan_input, evidence) -> coverage, findings

    Three-value detectors:
        run(scan_input) -> coverage, findings, evidence
    """

    if uses_shared_evidence:

        result = detector.run(
            scan_input,
            shared_evidence,
        )

        if not isinstance(result, tuple) or len(result) != 2:
            raise ValueError(
                f"{detector.__class__.__name__} "
                "must return (coverage, findings)."
            )

        coverage_item, detector_findings = result

    else:

        result = detector.run(scan_input)

        if not isinstance(result, tuple) or len(result) != 3:
            raise ValueError(
                f"{detector.__class__.__name__} "
                "must return (coverage, findings, evidence)."
            )

        (
            coverage_item,
            detector_findings,
            detector_evidence,
        ) = result

        if not isinstance(detector_evidence, list):
            raise TypeError(
                "Detector evidence must be returned as a list."
            )

        shared_evidence.extend(detector_evidence)

    if not isinstance(detector_findings, list):
        raise TypeError(
            "Detector findings must be returned as a list."
        )

    normalized_coverage = _normalize_coverage(
        coverage_item,
        detector,
    )

    return normalized_coverage, detector_findings


# ============================================================
# MAIN SECURITY SCAN ENGINE
# ============================================================

def run_security_scan(scan_input: dict) -> dict:
    """
    Run authorized OWASP API security checks.

    Public interface:
        run_security_scan(scan_input: dict) -> dict

    All ten OWASP categories are registered.

    Categories without sufficient testing context remain
    INCONCLUSIVE rather than being reported as PASS.
    """

    try:

        # ----------------------------------------------------
        # STEP 1: VALIDATE INPUT
        # ----------------------------------------------------

        validated_input = ScanInput.model_validate(scan_input)

        # ----------------------------------------------------
        # STEP 2: VALIDATE TARGET SCOPE
        # ----------------------------------------------------

        validate_scan_scope(validated_input)

        evidence: list[Evidence] = []
        findings = []
        detector_coverage = {}

        # ----------------------------------------------------
        # STEP 3: REGISTER ALL TEN DETECTORS
        # ----------------------------------------------------

        # True:
        # detector.run(scan_input, shared_evidence)
        #
        # False:
        # detector.run(scan_input)

        detectors = [
            (API1BOLADetector(), True),
            (API2BrokenAuthenticationDetector(), True),
            (API3BrokenObjectPropertyDetector(), False),
            (API4ResourceConsumptionDetector(), False),
            (API5BrokenFunctionAuthorizationDetector(), False),
            (API6SensitiveBusinessFlowsDetector(), False),
            (API7SSRFDetector(), False),
            (API8MisconfigurationDetector(), True),
            (API9InventoryManagementDetector(), False),
            (API10UnsafeConsumptionDetector(), False),
        ]

        # ----------------------------------------------------
        # STEP 4: EXECUTE DETECTORS INDEPENDENTLY
        # ----------------------------------------------------

        for detector, uses_shared_evidence in detectors:

            detector_id = getattr(
                detector,
                "owasp_id",
                "",
            ) or getattr(
                detector,
                "OWASP_ID",
                "",
            )

            if detector_id:
                detector_id = _canonical_owasp_id(detector_id)

            try:

                coverage_item, detector_findings = (
                    _execute_detector(
                        detector=detector,
                        scan_input=validated_input,
                        shared_evidence=evidence,
                        uses_shared_evidence=uses_shared_evidence,
                    )
                )

                # Use the canonical ID returned by normalization.
                coverage_id = _canonical_owasp_id(
                    coverage_item.owasp_id
                )

                detector_coverage[coverage_id] = coverage_item

                findings.extend(detector_findings)

            except Exception:
                # A failed detector must not be reported as PASS.

                category_name = next(
                    (
                        name
                        for owasp_id, name in OWASP_API_TOP_10_2023
                        if owasp_id == detector_id
                    ),
                    detector.__class__.__name__,
                )

                if not detector_id:
                    detector_id = "UNKNOWN"

                detector_coverage[detector_id] = Coverage(
                    owasp_id=detector_id,
                    category=category_name,
                    status=CheckStatus.INCONCLUSIVE,
                    reason=(
                        "Detector execution failed. "
                        "This category could not be reliably assessed."
                    ),
                )

        # ----------------------------------------------------
        # STEP 5: BUILD COVERAGE FOR ALL TEN CATEGORIES
        # ----------------------------------------------------

        coverage = []

        for owasp_id, category in OWASP_API_TOP_10_2023:

            coverage.append(
                detector_coverage.get(
                    owasp_id,
                    Coverage(
                        owasp_id=owasp_id,
                        category=category,
                        status=CheckStatus.INCONCLUSIVE,
                        reason=(
                            "Detector did not return a coverage result. "
                            "This category was not confirmed as tested."
                        ),
                    ),
                )
            )

        # ----------------------------------------------------
        # STEP 6: VALIDATE FINDING/EVIDENCE RELATIONSHIPS
        # ----------------------------------------------------

        _validate_evidence_integrity(
            findings,
            evidence,
        )

        # ----------------------------------------------------
        # STEP 7: GENERATE SUMMARY
        # ----------------------------------------------------

        summary = Summary(
            tested=len(coverage),

            passed=sum(
                item.status == CheckStatus.PASS
                for item in coverage
            ),

            failed=sum(
                item.status == CheckStatus.FAIL
                for item in coverage
            ),

            inconclusive=sum(
                item.status == CheckStatus.INCONCLUSIVE
                for item in coverage
            ),

            not_applicable=sum(
                item.status == CheckStatus.NOT_APPLICABLE
                for item in coverage
            ),
        )

        # ----------------------------------------------------
        # STEP 8: BUILD FINAL OUTPUT
        # ----------------------------------------------------

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
        # Safe failure response.
        # Do not expose internal exception details to API users.

        failed_coverage = [
            {
                "owasp_id": owasp_id,
                "category": category,
                "status": CheckStatus.INCONCLUSIVE.value,
                "reason": (
                    "Scan failed before this category "
                    "could be reliably assessed."
                ),
            }
            for owasp_id, category in OWASP_API_TOP_10_2023
        ]

        return {
            "scan_id": (
                scan_input.get("scan_id", "unknown")
                if isinstance(scan_input, dict)
                else "unknown"
            ),

            "status": ScanStatus.FAILED.value,

            "coverage": failed_coverage,

            "findings": [],

            "evidence": [],

            "summary": {
                "tested": 10,
                "passed": 0,
                "failed": 0,
                "inconclusive": 10,
                "not_applicable": 0,
            },

            "error": (
                "Scan could not be completed. Verify the input, "
                "authorization, scope, detector configuration, "
                "and target availability."
            ),

            "error_code": "SCAN_FAILED",
        }
