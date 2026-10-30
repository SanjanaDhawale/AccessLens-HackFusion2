from sqlalchemy import ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base
from backend.models.base import TimestampMixin


class Specification(Base, TimestampMixin):
    __tablename__ = "specifications"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    specification_id: Mapped[str] = mapped_column(
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

    status: Mapped[str] = mapped_column(
        String(30),
        default="PARSED",
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    openapi_version: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    endpoint_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    servers: Mapped[list] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    endpoints: Mapped[list] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )