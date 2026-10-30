
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


class API4ResourceConsumptionDetector(BaseDetector):
    """
    API4:2023 - Unrestricted Resource Consumption.

    Performs conservative, read-only checks for resource-related
    response indicators. It does not perform load testing,
    stress testing, or uncontrolled request generation.
    """

    owasp_id = "API4:2023"
    category = "Unrestricted Resource Consumption"

    RESOURCE_HEADERS = {
        "x-ratelimit-limit",
        "x-rate-limit-limit",
        "ratelimit-limit",
    }

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

        # Only explicitly configured GET endpoints are considered.
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
                    reason="No authorized GET endpoints are available for API4 checks.",
                ),
                findings,
                evidence_items,
            )

        try:
            # Strict request limit: at most five ordinary GET requests.
            client = SafeRequestClient(
                scan_input,
                max_requests=min(len(endpoints), 5),
            )

            inspected = 0

            for endpoint in endpoints[:5]:
                response = client.request(
                    "GET",
                    endpoint.path,
                    headers={},
                )

                if response.status_code < 200 or response.status_code >= 300:
                    continue

                inspected += 1

                headers = {
                    str(key).lower(): str(value)
                    for key, value in response.headers.items()
                }

                limit_headers = [
                    name
                    for name in self.RESOURCE_HEADERS
                    if name in headers
                ]

                # A missing rate-limit header alone does not prove
                # a vulnerability. This detector only records
                # observable resource-control information.
                if not limit_headers:
                    continue

                finding_id = f"FND-{uuid.uuid4().hex[:12]}"
                evidence_id = f"EVD-{uuid.uuid4().hex[:12]}"

                finding = Finding(
                    id=finding_id,
                    owasp_id=self.owasp_id,
                    title="Resource limit information observed",
                    severity=Severity.INFO,
                    status=CheckStatus.INCONCLUSIVE,
                    confidence=Confidence.LOW,
                    endpoint=endpoint.path,
                    method="GET",
                    evidence_id=evidence_id,
                    rationale=(
                        "The response exposes rate-limit metadata. "
                        "This is informational and does not establish "
                        "whether resource consumption is adequately restricted."
                    ),
                    remediation=(
                        "Verify server-side rate limits, pagination limits, "
                        "request size limits, execution timeouts, and "
                        "resource quotas using controlled authorized tests."
                    ),
                )

                safe_headers = {
                    key: value[:200]
                    for key, value in headers.items()
                    if key in self.RESOURCE_HEADERS
                }

                evidence = Evidence(
                    evidence_id=evidence_id,
                    finding_id=finding_id,
                    check_id="API4-RESOURCE-HEADERS",
                    request=EvidenceRequest(
                        method="GET",
                        url=response.url,
                        headers={},
                    ),
                    response=EvidenceResponse(
                        status_code=response.status_code,
                        headers=safe_headers,
                        body_excerpt="Response rate-limit metadata observed.",
                    ),
                    notes=(
                        "Only rate-limit header names and values were "
                        "retained. No response body was stored."
                    ),
                )

                findings.append(finding)
                evidence_items.append(evidence)

            if inspected == 0:
                status = CheckStatus.INCONCLUSIVE
                reason = "No successful responses were available for inspection."

            elif findings:
                status = CheckStatus.INCONCLUSIVE
                reason = (
                    "Rate-limit metadata was observed, but the presence "
                    "of headers does not prove effective resource protection."
                )

            else:
                status = CheckStatus.INCONCLUSIVE
                reason = (
                    "Responses were inspected, but resource limits "
                    "cannot be established using passive GET checks alone."
                )

            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=status,
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
                    reason="API4 resource inspection could not be completed.",
                ),
                findings,
                evidence_items,
            )
