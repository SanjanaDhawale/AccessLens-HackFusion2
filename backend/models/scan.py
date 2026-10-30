from sqlalchemy import ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base
from backend.models.base import TimestampMixin


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    scan_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    target_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("targets.target_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    specification_id: Mapped[str | None] = mapped_column(
            String(100),
            ForeignKey(
                "specifications.specification_id",
              ondelete="RESTRICT",
            ),
            nullable=True,
            index=True,
 )

    status: Mapped[str] = mapped_column(
        String(30),
        default="QUEUED",
        nullable=False,
        index=True,
    )

    progress: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    total_endpoints: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    completed_endpoints: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    metadata_json: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )