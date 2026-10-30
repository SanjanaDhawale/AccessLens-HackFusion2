
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


class API8MisconfigurationDetector(BaseDetector):
    """
    API8:2023 - Security Misconfiguration.

    Tests authorized endpoints for permissive wildcard CORS
    configuration using an explicit untrusted Origin header.
    """

    owasp_id = "API8:2023"
    category = "Security Misconfiguration"

    TEST_ORIGIN = "https://accesslens.invalid"

    def run(
        self,
        scan_input: ScanInput,
        evidence: list[Evidence],
    ) -> tuple[Coverage, list[Finding]]:

        if not scan_input.endpoints:
            return (
                self.inconclusive_coverage(
                    "No authorized endpoints were provided."
                ),
                [],
            )

        findings: list[Finding] = []
        tested = 0

        try:
            with SafeRequestClient(scan_input) as client:

                for endpoint in scan_input.endpoints:

                    if endpoint.method not in {
                        "GET",
                        "HEAD",
                        "OPTIONS",
                    }:
                        continue

                    # Send an explicit untrusted Origin.
                    response = client.request(
                        endpoint.method,
                        endpoint.path,
                        headers={
                            "Origin": self.TEST_ORIGIN,
                        },
                    )

                    tested += 1

                    headers = {
                        name.lower(): value.strip()
                        for name, value in response.headers.items()
                    }

                    origin = headers.get(
                        "access-control-allow-origin",
                        "",
                    )

                    credentials = headers.get(
                        "access-control-allow-credentials",
                        "",
                    ).lower()

                    allowed_headers = headers.get(
                        "access-control-allow-headers",
                        "",
                    ).lower()

                    # No wildcard CORS configuration observed.
                    if origin != "*":
                        continue

                    finding_id = (
                        f"API8-CORS-{uuid4().hex[:10].upper()}"
                    )

                    evidence_id = (
                        f"EVD-{uuid4().hex[:12].upper()}"
                    )

                    credentialed = credentials == "true"

                    authorization_allowed = (
                        "authorization" in allowed_headers
                        or "*" in allowed_headers
                    )

                    if credentialed:
                        severity = Severity.MEDIUM
                        title = (
                            "Wildcard CORS with credential support"
                        )
                        rationale = (
                            "The response contains a wildcard "
                            "Access-Control-Allow-Origin header "
                            "and enables credential support. "
                            "Browser exploitability requires "
                            "additional verification."
                        )
                    else:
                        severity = Severity.LOW
                        title = (
                            "Permissive wildcard CORS configuration"
                        )
                        rationale = (
                            "The server allows cross-origin requests "
                            "from any origin. This is a permissive "
                            "configuration. Exploitability has not "
                            "been established."
                        )

                    if authorization_allowed:
                        rationale += (
                            " The response also permits the "
                            "Authorization request header."
                        )

                    # Store sanitized evidence only.
                    evidence.append(
                        Evidence(
                            evidence_id=evidence_id,
                            finding_id=finding_id,
                            check_id="API8-CORS-001",
                            request=EvidenceRequest(
                                method=endpoint.method,
                                url=response.url,
                                headers={
                                    "Origin": self.TEST_ORIGIN,
                                },
                            ),
                            response=EvidenceResponse(
                                status_code=response.status_code,
                                headers=response.headers,
                                body_excerpt="",
                            ),
                            notes=(
                                "Wildcard CORS configuration observed "
                                "for an explicitly supplied test origin. "
                                "Authentication credentials and response "
                                "body were not stored."
                            ),
                        )
                    )

                    findings.append(
                        Finding(
                            id=finding_id,
                            owasp_id=self.owasp_id,
                            title=title,
                            severity=severity,
                            status=CheckStatus.FAIL,
                            confidence=Confidence.HIGH,
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            evidence_id=evidence_id,
                            rationale=rationale,
                            remediation=(
                                "Configure an explicit allowlist of "
                                "trusted origins. Permit only required "
                                "HTTP methods and request headers. "
                                "Avoid wildcard origins for sensitive "
                                "authenticated APIs."
                            ),
                        )
                    )

        except Exception as exc:
            return (
                self.inconclusive_coverage(
                    "API8 checks could not be completed. "
                    f"Error category: {type(exc).__name__}."
                ),
                findings,
            )

        if tested == 0:
            return (
                self.inconclusive_coverage(
                    "No supported safe HTTP methods were available."
                ),
                findings,
            )

        status = (
            CheckStatus.FAIL
            if findings
            else CheckStatus.PASS
        )

        return (
            Coverage(
                owasp_id=self.owasp_id,
                category=self.category,
                status=status,
                reason=(
                    f"Checked {tested} authorized endpoint(s) "
                    "for permissive wildcard CORS configuration."
                ),
            ),
            findings,
        )
