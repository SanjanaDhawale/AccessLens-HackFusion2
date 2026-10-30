
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


class API5BrokenFunctionAuthorizationDetector(BaseDetector):
    """
    API5:2023 - Broken Function Level Authorization.

    Performs safe, read-only checks against explicitly configured
    privileged GET endpoints.

    A response alone cannot prove a function is unauthorized.
    Therefore, successful access is reported as potential exposure
    with INCONCLUSIVE status until role-based authorization is verified.
    """

    owasp_id = "API5:2023"
    category = "Broken Function Level Authorization"

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

        # Only explicitly configured, authorized GET endpoints.
        endpoints = [
            endpoint
            for endpoint in scan_input.endpoints
            if endpoint.method == "GET"
            and endpoint.path in scan_input.allowed_paths
            and endpoint.path in scan_input.authentication_required_endpoints
        ]

        if not endpoints:
            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    reason=(
                        "No explicitly configured privileged GET endpoints "
                        "are available for API5 testing."
                    ),
                ),
                findings,
                evidence_items,
            )

        # A safe anonymous request can identify publicly accessible
        # privileged functions, but cannot establish role violations.
        from security_engine.request_client import SafeRequestClient

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

                finding_id = f"FND-{uuid.uuid4().hex[:12]}"
                evidence_id = f"EVD-{uuid.uuid4().hex[:12]}"

                finding = Finding(
                    id=finding_id,
                    owasp_id=self.owasp_id,
                    title="Potential public access to privileged function",
                    severity=Severity.MEDIUM,
                    status=CheckStatus.INCONCLUSIVE,
                    confidence=Confidence.LOW,
                    endpoint=endpoint.path,
                    method="GET",
                    evidence_id=evidence_id,
                    rationale=(
                        "An endpoint explicitly identified as "
                        "authentication-protected returned a successful "
                        "response without credentials. Verify whether "
                        "this function is intended to be publicly accessible "
                        "and whether role-based authorization is enforced."
                    ),
                    remediation=(
                        "Enforce server-side function-level authorization. "
                        "Verify user roles and permissions for every "
                        "privileged operation."
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
                    check_id="API5-ANONYMOUS-ACCESS",
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
                        "Anonymous access response recorded. "
                        "No response body or sensitive values were stored."
                    ),
                )

                findings.append(finding)
                evidence_items.append(evidence)

            if inconclusive_count:
                reason = "Some privileged endpoint checks were inconclusive."
            elif findings:
                reason = (
                    "Potential anonymous access was observed. "
                    "Role-based authorization requires further verification."
                )
            elif inspected:
                reason = (
                    "Configured endpoints rejected anonymous access. "
                    "This does not establish role-based authorization."
                )
            else:
                reason = "No API5 checks could be completed."

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
                    reason="API5 authorization checks could not be completed.",
                ),
                findings,
                evidence_items,
            )
