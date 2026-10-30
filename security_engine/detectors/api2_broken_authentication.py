from __future__ import annotations

from uuid import uuid4

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


class API2BrokenAuthenticationDetector(BaseDetector):
    """
    API2:2023 - Broken Authentication.

    Checks explicitly identified authentication-protected endpoints
    for unauthenticated access.

    Only GET and HEAD requests are permitted.
    No credentials are sent during these checks.
    """

    owasp_id = "API2:2023"
    category = "Broken Authentication"

    SAFE_METHODS = {"GET", "HEAD"}

    def run(
        self,
        scan_input: ScanInput,
        evidence: list[Evidence],
    ) -> tuple[Coverage, list[Finding]]:

        # Authorization must be explicitly confirmed.
        if not scan_input.authorization_context.authorization_confirmed:
            return (
                self.inconclusive_coverage(
                    "Authorization for security testing was not confirmed."
                ),
                [],
            )

        # Only explicitly protected endpoints may be tested.
        protected_paths = scan_input.authentication_required_endpoints

        if not protected_paths:
            return (
                self.inconclusive_coverage(
                    "No authentication-required endpoints were provided."
                ),
                [],
            )

        # Match protected paths against supplied endpoint definitions.
        endpoints = [
            endpoint
            for endpoint in scan_input.endpoints
            if (
                endpoint.path in protected_paths
                and endpoint.method in self.SAFE_METHODS
            )
        ]

        if not endpoints:
            return (
                self.inconclusive_coverage(
                    "No matching authentication-required GET or HEAD "
                    "endpoints were available."
                ),
                [],
            )

        findings: list[Finding] = []
        tested = 0
        rejected = 0
        inconclusive = 0

        try:
            with SafeRequestClient(
                scan_input,
                max_requests=min(len(endpoints), 20),
            ) as client:

                for endpoint in endpoints:

                    # Deliberately do not send Authorization or cookies.
                    response = client.request(
                        endpoint.method,
                        endpoint.path,
                    )

                    tested += 1

                    # Authentication correctly rejected the request.
                    if response.status_code in (401, 403):
                        rejected += 1
                        continue

                    # Successful access to an explicitly protected
                    # endpoint without credentials is a finding.
                    if 200 <= response.status_code < 300:

                        finding_id = (
                            f"API2-AUTH-{uuid4().hex[:10].upper()}"
                        )

                        evidence_id = (
                            f"EVD-{uuid4().hex[:12].upper()}"
                        )

                        evidence.append(
                            Evidence(
                                evidence_id=evidence_id,
                                finding_id=finding_id,
                                check_id="API2-AUTH-001",
                                request=EvidenceRequest(
                                    method=endpoint.method,
                                    url=response.url,
                                    headers={},
                                ),
                                response=EvidenceResponse(
                                    status_code=response.status_code,
                                    headers=response.headers,
                                    # Do not store potentially sensitive
                                    # response data for this check.
                                    body_excerpt="",
                                ),
                                notes=(
                                    "An explicitly protected endpoint "
                                    "returned a successful response "
                                    "without an Authorization header. "
                                    "No authentication credentials "
                                    "were sent or stored."
                                ),
                            )
                        )

                        findings.append(
                            Finding(
                                id=finding_id,
                                owasp_id=self.owasp_id,
                                title=(
                                    "Authentication Required Endpoint "
                                    "Accessible Without Credentials"
                                ),
                                severity=Severity.HIGH,
                                status=CheckStatus.FAIL,
                                confidence=Confidence.HIGH,
                                endpoint=endpoint.path,
                                method=endpoint.method,
                                evidence_id=evidence_id,
                                rationale=(
                                    "The endpoint was explicitly "
                                    "identified as requiring "
                                    "authentication, but returned "
                                    f"HTTP {response.status_code} "
                                    "without authentication credentials."
                                ),
                                remediation=(
                                    "Enforce authentication on every "
                                    "protected endpoint. Validate the "
                                    "authentication token or session "
                                    "before returning protected resources. "
                                    "Add automated tests to verify that "
                                    "unauthenticated requests are rejected."
                                ),
                            )
                        )

                        continue

                    # Other responses do not establish whether
                    # authentication is correctly enforced.
                    inconclusive += 1

        except Exception as exc:
            return (
                self.inconclusive_coverage(
                    "API2 checks could not be completed. "
                    f"Error category: {type(exc).__name__}."
                ),
                findings,
            )

        if tested == 0:
            return (
                self.inconclusive_coverage(
                    "No authentication checks were completed."
                ),
                findings,
            )

        if findings:
            status = CheckStatus.FAIL
            reason = (
                f"Checked {tested} protected endpoint(s). "
                f"Found {len(findings)} endpoint(s) accessible "
                "without authentication."
            )

        elif inconclusive > 0:
            status = CheckStatus.INCONCLUSIVE
            reason = (
                f"Checked {tested} protected endpoint(s). "
                f"{rejected} rejected unauthenticated access; "
                f"{inconclusive} returned inconclusive responses."
            )

        else:
            status = CheckStatus.PASS
            reason = (
                f"Checked {tested} explicitly protected endpoint(s). "
                "All rejected unauthenticated requests."
            )

        return (
            Coverage(
                owasp_id=self.owasp_id,
                category=self.category,
                status=status,
                reason=reason,
            ),
            findings,
        )