
from __future__ import annotations

import uuid

from security_engine.detectors.base import BaseDetector
from security_engine.models import (
    CheckStatus,
    Confidence,
    Coverage,
    Evidence,
    EvidenceRequest,
    EvidenceResponse,
    Finding,
    ScanInput,
    Severity,
)
from security_engine.request_client import SafeRequestClient


class API6SensitiveBusinessFlowsDetector(BaseDetector):
    """
    API6:2023 - Unrestricted Access to Sensitive Business Flows.

    Performs safe, read-only inspection of explicitly authorized
    business-flow GET endpoints.

    This detector does not automate purchases, bookings, account
    creation, transactions, or other state-changing activities.
    """

    owasp_id = "API6:2023"
    category = "Unrestricted Access to Sensitive Business Flows"

    def run(self, scan_input: ScanInput) -> tuple[
        Coverage,
        list[Finding],
        list[Evidence],
    ]:

        findings: list[Finding] = []
        evidence_items: list[Evidence] = []

        if not scan_input.authorization_context.authorization_confirmed:
            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    reason="Authorization for security testing is not confirmed.",
                ),
                findings,
                evidence_items,
            )

        endpoints = [
            endpoint
            for endpoint in scan_input.endpoints
            if endpoint.method == "GET"
            and endpoint.path in scan_input.allowed_paths
        ]

        if not endpoints:
            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    reason="No authorized GET endpoints are available for API6 inspection.",
                ),
                findings,
                evidence_items,
            )

        try:
            client = SafeRequestClient(
                scan_input,
                max_requests=min(len(endpoints), 5),
            )

            inspected = 0
            inconclusive_count = 0

            for endpoint in endpoints[:5]:

                response = client.request(
                    "GET",
                    endpoint.path,
                    headers={},
                )

                if response.status_code in {401, 403}:
                    inspected += 1
                    continue

                if not 200 <= response.status_code < 300:
                    inconclusive_count += 1
                    continue

                inspected += 1

                # A successful GET does not prove abuse of a
                # sensitive business flow. No vulnerability is
                # reported without a defined business-flow policy.
                finding_id = f"FND-{uuid.uuid4().hex[:12]}"
                evidence_id = f"EVD-{uuid.uuid4().hex[:12]}"

                finding = Finding(
                    id=finding_id,
                    owasp_id=self.owasp_id,
                    title="Sensitive business flow endpoint observed",
                    severity=Severity.INFO,
                    status=CheckStatus.INCONCLUSIVE,
                    confidence=Confidence.LOW,
                    endpoint=endpoint.path,
                    method="GET",
                    evidence_id=evidence_id,
                    rationale=(
                        "An authorized business-flow endpoint returned "
                        "a successful response. This observation alone "
                        "does not establish automated abuse or missing "
                        "business-flow protections."
                    ),
                    remediation=(
                        "Define business-flow abuse controls such as "
                        "per-user quotas, velocity limits, transaction "
                        "limits, bot detection, and anomaly monitoring. "
                        "Validate these controls using approved test cases."
                    ),
                )

                safe_headers = {
                    key: str(value)[:200]
                    for key, value in response.headers.items()
                    if key.lower() in {
                        "content-type",
                        "cache-control",
                        "x-content-type-options",
                    }
                }

                evidence = Evidence(
                    evidence_id=evidence_id,
                    finding_id=finding_id,
                    check_id="API6-BUSINESS-FLOW-OBSERVATION",
                    request=EvidenceRequest(
                        method="GET",
                        url=response.url,
                        headers={},
                    ),
                    response=EvidenceResponse(
                        status_code=response.status_code,
                        headers=safe_headers,
                        body_excerpt="Response body omitted.",
                    ),
                    notes=(
                        "Only response status and selected headers "
                        "were retained. No business transaction was executed."
                    ),
                )

                findings.append(finding)
                evidence_items.append(evidence)

            if inconclusive_count:
                reason = "Some business-flow endpoint inspections were inconclusive."
            elif inspected:
                reason = (
                    "Business-flow endpoints were inspected. "
                    "Abuse protections cannot be established using "
                    "read-only requests alone."
                )
            else:
                reason = "No API6 checks could be completed."

            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    reason=reason,
                ),
                findings,
                evidence_items,
            )

        except Exception:
            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    reason="API6 business-flow inspection could not be completed.",
                ),
                findings,
                evidence_items,
            )
