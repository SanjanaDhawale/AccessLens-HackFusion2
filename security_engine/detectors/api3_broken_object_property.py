
from __future__ import annotations

import json
import uuid
from typing import Any

from security_engine.credential_store import resolve_bearer_token
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
from security_engine.redaction import redact_text
from security_engine.request_client import SafeRequestClient


class API3BrokenObjectPropertyDetector(BaseDetector):
    """
    API3:2023 - Broken Object Property Level Authorization.

    Safe implementation:
    - Uses explicitly configured GET endpoints.
    - Uses configured credential references.
    - Checks only explicitly configured sensitive properties.
    - Does not modify API objects.
    """

    owasp_id = "API3:2023"
    category = "Broken Object Property Level Authorization"

    def _get_nested_property(
        self,
        data: Any,
        property_path: str,
    ) -> tuple[bool, Any]:
        """Read a nested JSON property using dot notation."""

        current = data

        for part in property_path.split("."):
            if not isinstance(current, dict) or part not in current:
                return False, None

            current = current[part]

        return True, current

    def _parse_json(self, body: str) -> Any | None:
        """Parse a JSON response safely."""

        if not body:
            return None

        try:
            return json.loads(body)
        except (json.JSONDecodeError, TypeError, ValueError):
            return None

    def _make_evidence(
        self,
        finding_id: str,
        check_id: str,
        endpoint: str,
        response: Any,
        exposed_properties: list[str],
    ) -> Evidence:
        """Create evidence without storing sensitive response values."""

        safe_headers = {}

        for key, value in response.headers.items():
            if key.lower() in {
                "content-type",
                "cache-control",
                "x-content-type-options",
            }:
                safe_headers[key] = str(value)[:200]

        return Evidence(
            evidence_id=f"EVD-{uuid.uuid4().hex[:12]}",
            finding_id=finding_id,
            check_id=check_id,
            request=EvidenceRequest(
                method="GET",
                url=endpoint,
                headers={
                    "Authorization": "[REDACTED]"
                },
            ),
            response=EvidenceResponse(
                status_code=response.status_code,
                headers=safe_headers,
                body_excerpt=(
                    "Configured sensitive properties present: "
                    + ", ".join(exposed_properties)
                ),
            ),
            notes=(
                "Sensitive response values were not stored. "
                "Only configured property names and response status "
                "were retained."
            ),
        )

    def run(self, scan_input: ScanInput) -> tuple[
        Coverage,
        list[Finding],
        list[Evidence],
    ]:

        findings: list[Finding] = []
        evidence_items: list[Evidence] = []

        config = scan_input.bopla_test

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

        if not config or not config.tests:
            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    reason=(
                        "No explicitly configured API3 sensitive-property "
                        "tests were provided."
                    ),
                ),
                findings,
                evidence_items,
            )

        completed_checks = 0
        inconclusive_checks = 0

        try:
            client = SafeRequestClient(
                scan_input,
                max_requests=min(len(config.tests), 20),
            )

            for test in config.tests:

                endpoint = test.endpoint_path

                matching_endpoint = next(
                    (
                        item
                        for item in scan_input.endpoints
                        if item.path == endpoint
                        and item.method == "GET"
                    ),
                    None,
                )

                if matching_endpoint is None:
                    inconclusive_checks += 1
                    continue

                if endpoint not in scan_input.allowed_paths:
                    inconclusive_checks += 1
                    continue

                try:
                    token = resolve_bearer_token(
                        test.credential_ref
                    )
                except Exception:
                    inconclusive_checks += 1
                    continue

                if not token:
                    inconclusive_checks += 1
                    continue

                response = client.request(
                    "GET",
                    endpoint,
                    headers={
                        "Authorization": f"Bearer {token}"
                    },
                )

                if response.status_code in {401, 403}:
                    # The authenticated identity could not access
                    # the configured endpoint.
                    inconclusive_checks += 1
                    continue

                if response.status_code < 200 or response.status_code >= 300:
                    inconclusive_checks += 1
                    continue

                parsed_data = self._parse_json(response.body_excerpt)

                if parsed_data is None:
                    inconclusive_checks += 1
                    continue

                exposed_properties = []

                for property_path in test.forbidden_properties:
                    exists, _ = self._get_nested_property(
                        parsed_data,
                        property_path,
                    )

                    if exists:
                        exposed_properties.append(property_path)

                completed_checks += 1

                if exposed_properties:
                    finding_id = f"FND-{uuid.uuid4().hex[:12]}"
                    check_id = test.test_id

                    finding = Finding(
                        id=finding_id,
                        owasp_id=self.owasp_id,
                        title=(
                            "Potential sensitive object property exposure"
                        ),
                        severity=Severity.HIGH,
                        status=CheckStatus.FAIL,
                        confidence=Confidence.HIGH,
                        endpoint=endpoint,
                        method="GET",
                        evidence_id=f"EVD-{uuid.uuid4().hex[:12]}",
                        rationale=(
                            "The authenticated API response contains "
                            "configured sensitive properties: "
                            + ", ".join(exposed_properties)
                            + ". Their authorization and business "
                            "necessity must be verified."
                        ),
                        remediation=(
                            "Apply property-level authorization and "
                            "response allowlists. Return only fields "
                            "required by the authenticated user's role."
                        ),
                    )

                    evidence = self._make_evidence(
                        finding_id=finding.id,
                        check_id=check_id,
                        endpoint=endpoint,
                        response=response,
                        exposed_properties=exposed_properties,
                    )

                    # Keep finding and evidence identifiers linked.
                    finding.evidence_id = evidence.evidence_id

                    findings.append(finding)
                    evidence_items.append(evidence)

        except Exception:
            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=CheckStatus.INCONCLUSIVE,
                    reason=(
                        "API3 testing was interrupted. "
                        "Any confirmed findings were retained."
                    ),
                ),
                findings,
                evidence_items,
            )

        if findings:
            status = CheckStatus.FAIL
            reason = (
                "One or more configured sensitive properties "
                "were present in API responses. Authorization "
                "must be verified."
            )

        elif inconclusive_checks:
            status = CheckStatus.INCONCLUSIVE
            reason = (
                "Some API3 checks could not be completed reliably."
            )

        elif completed_checks:
            status = CheckStatus.PASS
            reason = (
                "No configured sensitive properties were found "
                "in the successfully inspected responses."
            )

        else:
            status = CheckStatus.INCONCLUSIVE
            reason = "No API3 checks could be completed."

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
