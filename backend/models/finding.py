from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base
from backend.models.base import TimestampMixin


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    finding_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    scan_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("scans.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    owasp_id: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )

    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    endpoint: Mapped[str] = mapped_column(
        String(2000),
        nullable=False,
    )

    method: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    evidence_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    remediation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )