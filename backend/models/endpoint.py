from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base
from backend.models.base import TimestampMixin


class Endpoint(Base, TimestampMixin):
    __tablename__ = "endpoints"

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "method",
            "path",
            name="uq_endpoint_scan_method_path",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    scan_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("scans.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    path: Mapped[str] = mapped_column(
        String(2000),
        nullable=False,
    )

    method: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )