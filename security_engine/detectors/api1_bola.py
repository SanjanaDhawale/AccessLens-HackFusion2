
from __future__ import annotations

import json
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
from security_engine.credential_store import (
    resolve_bearer_token,
)


class API1BOLADetector(BaseDetector):
    """Safely test object-level authorization using two identities."""

    owasp_id = "API1:2023"
    category = "Broken Object Level Authorization"

    @staticmethod
    def _parse_object(body: str) -> dict | None:
        try:
            value = json.loads(body)
            return value if isinstance(value, dict) else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _object_id(data: dict) -> str | None:
        for key in ("carId", "uuid", "objectId", "id"):
            value = data.get(key)
            if value is not None:
                return str(value)
        return None

    @staticmethod
    def _protected_data(data: dict) -> dict:
        sensitive_keys = {
            "vehicleLocation",
            "fullName",
            "email",
            "vin",
            "pincode",
            "owner",
            "previousOwners",
        }
        return {
            key: data[key]
            for key in sensitive_keys
            if key in data
        }

    @staticmethod
    def _safe_excerpt(body: str) -> str:
        """Remove personal and location data before storing evidence."""
        data = API1BOLADetector._parse_object(body)

        if data is None:
            return "[Response body omitted: unable to safely sanitize.]"

        sensitive_keys = {
            "email",
            "fullName",
            "latitude",
            "longitude",
            "vin",
            "pincode",
            "owner",
            "previousOwners",
            "vehicleLocation",
        }

        def sanitize(value):
            if isinstance(value, dict):
                return {
                    key: (
                        "[REDACTED]"
                        if key in sensitive_keys
                        else sanitize(item)
                    )
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [sanitize(item) for item in value]
            return value

        return json.dumps(sanitize(data))[:2000]

    def run(
        self,
        scan_input: ScanInput,
        evidence: list[Evidence],
    ) -> tuple[Coverage, list[Finding]]:

        config = scan_input.bola_test

        if config is None:
            return (
                self.inconclusive_coverage(
                    "BOLA configuration was not supplied. "
                    "No cross-account requests were sent."
                ),
                [],
            )

        identities = {
            identity.identity_id: identity
            for identity in config.identities
        }

        owner_case = next(
            case for case in config.test_cases
            if case.access_type == "OWNER_ACCESS"
        )
        cross_case = next(
            case for case in config.test_cases
            if case.access_type == "CROSS_ACCOUNT_ACCESS"
        )

        owner_identity = identities[owner_case.identity_id]
        cross_identity = identities[cross_case.identity_id]

        path = config.object_reference.read_path
        expected_id = config.object_reference.object_id

        finding_id = f"API1-{uuid4().hex[:12].upper()}"
        new_findings = []

        try:
            owner_token = resolve_bearer_token(
                owner_identity.credential_ref
            )
            cross_token = resolve_bearer_token(
                cross_identity.credential_ref
            )

            with SafeRequestClient(scan_input) as client:
                # Step 1: Owner positive control must succeed.
                owner_response = client.request(
                    "GET",
                    path,
                    headers={
                        "Authorization": f"Bearer {owner_token}"
                    },
                )

                if not 200 <= owner_response.status_code < 300:
                    return (
                        self.inconclusive_coverage(
                            "Owner positive control did not succeed. "
                            "Cross-account testing was not performed."
                        ),
                        [],
                    )

                owner_data = self._parse_object(
                    owner_response.body_excerpt
                )

                if (
                    owner_data is None
                    or self._object_id(owner_data) != expected_id
                ):
                    return (
                        self.inconclusive_coverage(
                            "Owner response did not verify the expected "
                            "object. Cross-account testing was not performed."
                        ),
                        [],
                    )

                owner_protected = self._protected_data(owner_data)

                if not owner_protected:
                    return (
                        self.inconclusive_coverage(
                            "Owner response did not expose verifiable "
                            "protected object data."
                        ),
                        [],
                    )

                # Step 2: Test the same object using the other identity.
                cross_response = client.request(
                    "GET",
                    path,
                    headers={
                        "Authorization": f"Bearer {cross_token}"
                    },
                )

            if cross_response.status_code in (401, 403):
                return (
                    Coverage(
                        owasp_id=self.owasp_id,
                        category=self.category,
                        status=CheckStatus.PASS,
                        reason=(
                            "Owner access succeeded and cross-account "
                            "access was denied."
                        ),
                    ),
                    [],
                )

            if not 200 <= cross_response.status_code < 300:
                return (
                    self.inconclusive_coverage(
                        "Cross-account response did not provide enough "
                        "information to determine authorization."
                    ),
                    [],
                )

            cross_data = self._parse_object(
                cross_response.body_excerpt
            )

            if (
                cross_data is None
                or self._object_id(cross_data) != expected_id
            ):
                return (
                    self.inconclusive_coverage(
                        "Cross-account response did not verify the "
                        "same protected object."
                    ),
                    [],
                )

            cross_protected = self._protected_data(cross_data)

            if (
                not cross_protected
                or cross_protected != owner_protected
            ):
                return (
                    self.inconclusive_coverage(
                        "Cross-account response did not sufficiently "
                        "match the owner's protected object data."
                    ),
                    [],
                )

            # Step 3: Confirmed cross-account data exposure.
            evidence_id = f"EVD-{uuid4().hex[:12].upper()}"

            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    finding_id=finding_id,
                    check_id=self.owasp_id,
                    request=EvidenceRequest(
                        method="GET",
                        url=cross_response.url,
                        headers={
                            "Authorization": "[REDACTED]"
                        },
                    ),
                    response=EvidenceResponse(
                        status_code=cross_response.status_code,
                        headers=cross_response.headers,
                        body_excerpt=self._safe_excerpt(
                            cross_response.body_excerpt
                        ),
                    ),
                    notes=(
                        "Owner positive control succeeded. The second "
                        "identity received the same protected object "
                        "data. Sensitive response values were redacted."
                    ),
                )
            )

            new_findings.append(
                Finding(
                    id=finding_id,
                    owasp_id=self.owasp_id,
                    title="Broken Object Level Authorization",
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    confidence=Confidence.CONFIRMED,
                    endpoint=path,
                    method="GET",
                    evidence_id=evidence_id,
                    rationale=(
                        "The owner successfully accessed the object. "
                        "A different authenticated identity also accessed "
                        "the same object and received matching protected "
                        "object data."
                    ),
                    remediation=(
                        "Enforce object-level authorization on every "
                        "request. Verify that the authenticated user owns "
                        "or is explicitly authorized to access the "
                        "requested object."
                    ),
                )
            )

            return (
                Coverage(
                    owasp_id=self.owasp_id,
                    category=self.category,
                    status=CheckStatus.FAIL,
                    reason=(
                        "Confirmed unauthorized cross-account access "
                        "to the owner's protected object."
                    ),
                ),
                new_findings,
            )

        except Exception:
            return (
                self.inconclusive_coverage(
                    "BOLA testing could not be completed due to a "
                    "credential, scope, or request error. Sensitive "
                    "error details were not exposed."
                ),
                [],
            )
