
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


class API7SSRFDetector:
    """Safe, passive API7 SSRF assessment."""

    CATEGORY = "Server Side Request Forgery"
    OWASP_ID = "API7:2023"

    def run(self, scan_input: ScanInput):
        findings: list[Finding] = []
        evidence_items: list[Evidence] = []

        coverage = {
            "owasp_id": self.OWASP_ID,
            "category": self.CATEGORY,
            "status": CheckStatus.INCONCLUSIVE,
            "reason": "Active SSRF testing was not performed.",
        }

        if not scan_input.authorization_context.authorization_confirmed:
            coverage["reason"] = (
                "Authorization was not confirmed. SSRF assessment skipped."
            )
            return coverage, findings, evidence_items

        if not scan_input.endpoints:
            coverage["reason"] = (
                "No API endpoints were supplied for SSRF assessment."
            )
            return coverage, findings, evidence_items

        # Inspect endpoint metadata only. Do not send SSRF payloads.
        endpoint = scan_input.endpoints[0]

        finding_id = str(uuid4())
        evidence_id = str(uuid4())

        evidence_items.append(
            Evidence(
                evidence_id=evidence_id,
                finding_id=finding_id,
                check_id=self.OWASP_ID,
                request=EvidenceRequest(
                    method=endpoint.method,
                    url=f"{scan_input.target_url}{endpoint.path}",
                    headers={},
                ),
                response=EvidenceResponse(
                    status_code=None,
                    headers={},
                    body_excerpt="",
                ),
                notes=(
                    "No network request or SSRF payload was sent. "
                    "Only supplied endpoint metadata was inspected. "
                    "Response data is intentionally empty."
                ),
            )
        )

        findings.append(
            Finding(
                id=finding_id,
                owasp_id=self.OWASP_ID,
                title="SSRF protection not verified",
                severity=Severity.INFO,
                status=CheckStatus.INCONCLUSIVE,
                confidence=Confidence.LOW,
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence_id=evidence_id,
                rationale=(
                    "The endpoint inventory alone cannot establish "
                    "whether server-side URL fetching is vulnerable. "
                    "No active SSRF test was performed."
                ),
                remediation=(
                    "For a controlled assessment, use an explicitly "
                    "authorized callback target. Validate destination "
                    "allowlists, block unauthorized internal destinations, "
                    "and enforce outbound network restrictions."
                ),
            )
        )

        coverage["reason"] = (
            "Endpoint metadata was inspected. No active SSRF testing "
            "was performed, so protection remains INCONCLUSIVE."
        )

        return coverage, findings, evidence_items
