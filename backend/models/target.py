from sqlalchemy import Boolean, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import TimestampMixin
from backend.database import Base


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    target_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    target_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    authorization_confirmed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    authorized_hosts: Mapped[list] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    allowed_paths: Mapped[list] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )