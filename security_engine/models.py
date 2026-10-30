
from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)


class ScanStatus(str, Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class EndpointSource(str, Enum):
    OPENAPI = "OPENAPI"
    AUTHORIZED_DISCOVERY = "AUTHORIZED_DISCOVERY"
    USER_PROVIDED = "USER_PROVIDED"


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    method: str
    operation_id: str | None = None
    source: EndpointSource

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError("Endpoint path must begin with a single '/'")

        if "\\" in value or any(
            ord(char) < 32 or ord(char) == 127 for char in value
        ):
            raise ValueError("Invalid endpoint path")

        return value

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.upper()

        if method not in {
            "GET", "HEAD", "OPTIONS", "POST",
            "PUT", "PATCH", "DELETE"
        }:
            raise ValueError("Unsupported HTTP method")

        return method


class AuthorizationContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorization_confirmed: bool
    credentials_available: bool = False


# ============================================================
# API1:2023 - BOLA OPTIONAL CONFIGURATION
# ============================================================

class BOLAIdentity(BaseModel):
    """Reference to one independently authenticated test identity."""

    model_config = ConfigDict(extra="forbid")

    identity_id: Literal["user_a", "user_b"]
    credential_ref: str = Field(min_length=1, max_length=100)

    @field_validator("credential_ref")
    @classmethod
    def validate_credential_ref(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", value):
            raise ValueError("Invalid credential reference")

        return value


class BOLAObjectReference(BaseModel):
    """One explicitly authorized object for BOLA testing."""

    model_config = ConfigDict(extra="forbid")

    object_id: str = Field(min_length=1, max_length=128)
    object_type: str = Field(min_length=1, max_length=64)
    owner_identity_id: Literal["user_a", "user_b"]
    read_path: str = Field(min_length=2, max_length=2048)

    @field_validator("object_id", "object_type")
    @classmethod
    def validate_object_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Object reference cannot be blank")

        if any(
            ord(char) < 32 or ord(char) == 127 for char in value
        ):
            raise ValueError("Invalid object reference value")

        return value

    @field_validator("read_path")
    @classmethod
    def validate_read_path(cls, value: str) -> str:
        parsed = urlsplit(value)
        decoded_path = unquote(parsed.path)

        if (
            not value.startswith("/")
            or value.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or "\\" in decoded_path
            or any(
                ord(char) < 32 or ord(char) == 127
                for char in decoded_path
            )
            or any(
                part in {".", ".."}
                for part in decoded_path.split("/")
            )
        ):
            raise ValueError("Invalid BOLA read path")

        return value


class BOLATestCase(BaseModel):
    """One explicitly defined authorization test."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1, max_length=64)
    identity_id: Literal["user_a", "user_b"]

    access_type: Literal[
        "OWNER_ACCESS",
        "CROSS_ACCOUNT_ACCESS"
    ]

    expected_access: Literal["ALLOW", "DENY"]


class BOLATestConfig(BaseModel):
    """Optional two-identity BOLA test configuration."""

    model_config = ConfigDict(extra="forbid")

    identities: list[BOLAIdentity] = Field(
        min_length=2,
        max_length=2,
    )

    object_reference: BOLAObjectReference

    test_cases: list[BOLATestCase] = Field(
        min_length=2,
        max_length=2,
    )

    @field_validator("identities")
    @classmethod
    def validate_identities(
        cls,
        value: list[BOLAIdentity],
    ) -> list[BOLAIdentity]:

        identity_ids = {
            identity.identity_id for identity in value
        }

        credential_refs = {
            identity.credential_ref for identity in value
        }

        if identity_ids != {"user_a", "user_b"}:
            raise ValueError(
                "Both user_a and user_b identities are required"
            )

        if len(credential_refs) != 2:
            raise ValueError(
                "Each identity needs a separate credential reference"
            )

        return value

    @model_validator(mode="after")
    def validate_test_configuration(self) -> "BOLATestConfig":

        if len({case.case_id for case in self.test_cases}) != 2:
            raise ValueError("BOLA test case IDs must be unique")

        owner_cases = [
            case for case in self.test_cases
            if case.access_type == "OWNER_ACCESS"
        ]

        cross_cases = [
            case for case in self.test_cases
            if case.access_type == "CROSS_ACCOUNT_ACCESS"
        ]

        if len(owner_cases) != 1 or len(cross_cases) != 1:
            raise ValueError(
                "Exactly one OWNER_ACCESS and one "
                "CROSS_ACCOUNT_ACCESS case are required"
            )

        owner_case = owner_cases[0]
        cross_case = cross_cases[0]

        if owner_case.expected_access != "ALLOW":
            raise ValueError(
                "OWNER_ACCESS must expect ALLOW"
            )

        if cross_case.expected_access != "DENY":
            raise ValueError(
                "CROSS_ACCOUNT_ACCESS must expect DENY"
            )

        actual_owner = self.object_reference.owner_identity_id

        if owner_case.identity_id != actual_owner:
            raise ValueError(
                "Owner test identity must match object owner"
            )

        if cross_case.identity_id == actual_owner:
            raise ValueError(
                "Cross-account identity must not own the object"
            )

        return self


# ============================================================
# SCAN INPUT
# ============================================================

class ScanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(min_length=1)
    target_url: str
    authorized_hosts: list[str] = Field(min_length=1)
    allowed_paths: list[str] = Field(min_length=1)
    endpoints: list[Endpoint]
    scan_profile: str
    authorization_context: AuthorizationContext

    # Optional extension: existing scan requests remain compatible.
    bola_test: BOLATestConfig | None = None

    # Private/loopback targets are denied unless explicitly authorized.
    # For an isolated lab, list every permitted resolved IP address.
    allow_private_targets: bool = False
    authorized_ips: list[str] = Field(default_factory=list)

    @field_validator("authorized_ips")
    @classmethod
    def validate_authorized_ips(cls, values: list[str]) -> list[str]:
        import ipaddress

        normalized = []
        for value in values:
            try:
                normalized.append(str(ipaddress.ip_address(value.strip())))
            except ValueError as exc:
                raise ValueError("authorized_ips must contain valid IP addresses") from exc
        if len(normalized) != len(set(normalized)):
            raise ValueError("authorized_ips must not contain duplicates")
        return normalized

    @field_validator("scan_id")
    @classmethod
    def validate_scan_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("scan_id cannot be blank")

        return value

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        parsed = HttpUrl(value)

        if parsed.scheme not in {"http", "https"}:
            raise ValueError(
                "Only HTTP and HTTPS targets are allowed"
            )

        if parsed.username or parsed.password:
            raise ValueError(
                "Target URL must not contain credentials"
            )

        return str(parsed).rstrip("/")

    @field_validator("authorized_hosts")
    @classmethod
    def normalize_hosts(cls, values: list[str]) -> list[str]:
        normalized = [
            host.strip().lower().rstrip(".")
            for host in values
        ]

        if any(not host for host in normalized):
            raise ValueError(
                "Authorized hosts cannot be blank"
            )

        return normalized

    @field_validator("allowed_paths")
    @classmethod
    def validate_allowed_paths(
        cls,
        values: list[str],
    ) -> list[str]:

        for path in values:
            if (
                not path.startswith("/")
                or path.startswith("//")
                or "\\" in path
                or any(
                    part in {".", ".."}
                    for part in unquote(path).split("/")
                )
            ):
                raise ValueError(
                    f"Invalid allowed path: {path}"
                )

        return values

    @field_validator("scan_profile")
    @classmethod
    def validate_profile(cls, value: str) -> str:
        if value != "OWASP_API_TOP_10_SAFE":
            raise ValueError("Unsupported scan profile")

        return value


# ============================================================
# COVERAGE, FINDINGS AND EVIDENCE
# ============================================================

class Coverage(BaseModel):
    owasp_id: str
    category: str
    status: CheckStatus
    reason: str


class Finding(BaseModel):
    id: str
    owasp_id: str
    title: str
    severity: Severity
    status: CheckStatus
    confidence: Confidence
    endpoint: str
    method: str
    evidence_id: str
    rationale: str
    remediation: str


class EvidenceRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)


class EvidenceResponse(BaseModel):
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str = ""


class Evidence(BaseModel):
    evidence_id: str
    finding_id: str
    check_id: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    request: EvidenceRequest
    response: EvidenceResponse
    notes: str = "Sensitive values have been redacted."


# ============================================================
# SUMMARY AND OUTPUT
# ============================================================

class Summary(BaseModel):
    tested: int = 0
    passed: int = 0
    failed: int = 0
    inconclusive: int = 0
    not_applicable: int = 0


class ScanOutput(BaseModel):
    scan_id: str
    status: ScanStatus
    coverage: list[Coverage] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    summary: Summary = Field(default_factory=Summary)


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    """Return JSON-compatible model data."""
    return model.model_dump(mode="json")
