
from __future__ import annotations

from uuid import uuid4

from security_engine.models import (
    CheckStatus,
    Confidence,
    Evidence,
    EvidenceRequest,
    EvidenceResponse,
    Finding,
    ScanInput,
    Severity,
)


class API9InventoryManagementDetector:
    """Compare supplied OpenAPI and authorized discovery inventories."""

    OWASP_ID = "API9:2023"
    CATEGORY = "Improper Inventory Management"

    def run(self, scan_input: ScanInput):
        findings: list[Finding] = []
        evidence_items: list[Evidence] = []

        if not scan_input.authorization_context.authorization_confirmed:
            return (
                {
                    "owasp_id": self.OWASP_ID,
                    "category": self.CATEGORY,
                    "status": CheckStatus.INCONCLUSIVE,
                    "reason": "Authorization was not confirmed.",
                },
                findings,
                evidence_items,
            )

        openapi_items = {
            (item.path, item.method)
            for item in scan_input.endpoints
            if item.source.value == "OPENAPI"
        }

        discovered_items = {
            (item.path, item.method)
            for item in scan_input.endpoints
            if item.source.value == "AUTHORIZED_DISCOVERY"
        }

        if not openapi_items or not discovered_items:
            return (
                {
                    "owasp_id": self.OWASP_ID,
                    "category": self.CATEGORY,
                    "status": CheckStatus.INCONCLUSIVE,
                    "reason": (
                        "Both OpenAPI and authorized discovery inventories "
                        "are required for comparison. A single inventory "
                        "cannot prove that undocumented endpoints do not exist."
                    ),
                },
                findings,
                evidence_items,
            )

        undocumented = discovered_items - openapi_items
        stale_documentation = openapi_items - discovered_items

        if not undocumented and not stale_documentation:
            return (
                {
                    "owasp_id": self.OWASP_ID,
                    "category": self.CATEGORY,
                    "status": CheckStatus.PASS,
                    "reason": (
                        "The supplied OpenAPI and authorized discovery "
                        "inventories match. This does not prove that the "
                        "inventories are complete."
                    ),
                },
                findings,
                evidence_items,
            )

        differences = []

        for path, method in sorted(undocumented):
            differences.append(
                f"Discovered but undocumented: {method} {path}"
            )

        for path, method in sorted(stale_documentation):
            differences.append(
                f"Documented but not discovered: {method} {path}"
            )

        finding_id = str(uuid4())
        evidence_id = str(uuid4())

        sample_path, sample_method = sorted(
            undocumented or stale_documentation
        )[0]

        evidence_items.append(
            Evidence(
                evidence_id=evidence_id,
                finding_id=finding_id,
                check_id=self.OWASP_ID,
                request=EvidenceRequest(
                    method=sample_method,
                    url=f"{scan_input.target_url}{sample_path}",
                    headers={},
                ),
                response=EvidenceResponse(
                    status_code=None,
                    headers={},
                    body_excerpt="",
                ),
                notes=(
                    "Inventory comparison only. No additional network "
                    "requests were sent. Differences: "
                    + "; ".join(differences[:10])
                ),
            )
        )

        findings.append(
            Finding(
                id=finding_id,
                owasp_id=self.OWASP_ID,
                title="API inventory mismatch detected",
                severity=Severity.INFO,
                status=CheckStatus.INCONCLUSIVE,
                confidence=Confidence.LOW,
                endpoint=sample_path,
                method=sample_method,
                evidence_id=evidence_id,
                rationale=(
                    "The supplied OpenAPI and authorized discovery "
                    "inventories contain differences. These differences "
                    "require review and do not independently prove a "
                    "security vulnerability."
                ),
                remediation=(
                    "Review undocumented and stale endpoints. Update "
                    "the API inventory, verify ownership, remove retired "
                    "routes where appropriate, and document API versions "
                    "and deprecation status."
                ),
            )
        )

        return (
            {
                "owasp_id": self.OWASP_ID,
                "category": self.CATEGORY,
                "status": CheckStatus.INCONCLUSIVE,
                "reason": (
                    "Inventory differences were identified. Manual review "
                    "is required; inventory completeness is not established."
                ),
            },
            findings,
            evidence_items,
        )
