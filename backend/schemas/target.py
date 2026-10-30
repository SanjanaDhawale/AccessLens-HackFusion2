from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlsplit


class TargetRegistrationRequest(BaseModel):
    target_url: str
    authorization_confirmed: bool
    authorized_hosts: list[str] = Field(min_length=1)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        parsed = urlsplit(value)

        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.hostname:
            raise ValueError("A valid target hostname is required.")

        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in target URLs.")

        if parsed.query or parsed.fragment:
            raise ValueError("Target URL must not contain query or fragment.")

        return value.rstrip("/")

    @field_validator("authorized_hosts")
    @classmethod
    def normalize_hosts(cls, values: list[str]) -> list[str]:
        return [host.strip().lower() for host in values if host.strip()]

    @field_validator("allowed_paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("At least one allowed path is required.")

        if any(not path.startswith("/") for path in values):
            raise ValueError("Allowed paths must begin with '/'.")

        return values


class TargetRegistrationResponse(BaseModel):
    target_id: str
    target_url: str
    status: Literal["REGISTERED"]
    authorization_confirmed: bool
    authorized_hosts: list[str]
    allowed_paths: list[str]
    created_at: datetime


def create_target_record(request: TargetRegistrationRequest) -> dict:
    return {
        "target_id": str(uuid4()),
        "target_url": request.target_url,
        "status": "REGISTERED",
        "authorization_confirmed": request.authorization_confirmed,
        "authorized_hosts": request.authorized_hosts,
        "allowed_paths": request.allowed_paths,
        "created_at": datetime.now(timezone.utc)
    }