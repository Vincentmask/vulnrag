from __future__ import annotations

from datetime import datetime

from sqlalchemy import (DateTime, ForeignKey, Index, String, Text,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Package(Base):
    __tablename__ = "packages"
    __table_args__ = (
        UniqueConstraint("ecosystem", "normalized_name",
                         name="uq_package_ecosystem_normalized"),
        Index("ix_package_ecosystem_normalized",
              "ecosystem", "normalized_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(255), nullable=False)

    advisories: Mapped[list[Advisory]] = relationship(
        back_populates="package", cascade="all, delete-orphan")


class Advisory(Base):
    __tablename__ = "advisories"
    __table_args__ = (
        UniqueConstraint("package_id", "source", "source_advisory_id",
                         name="uq_advisory_source_id_per_package"),
        Index("ix_advisory_source_id", "source", "source_advisory_id"),
        Index("ix_advisory_package_id", "package_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    package_id: Mapped[int] = mapped_column(ForeignKey(
        "packages.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_advisory_id: Mapped[str] = mapped_column(
        String(128), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)

    package: Mapped[Package] = relationship(back_populates="advisories")
    aliases: Mapped[list[AdvisoryAlias]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan")
    version_ranges: Mapped[list[VersionRange]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan")
    references: Mapped[list[Reference]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan")


class AdvisoryAlias(Base):
    __tablename__ = "advisory_aliases"
    __table_args__ = (
        UniqueConstraint("advisory_id", "alias", name="uq_advisory_alias"),
        Index("ix_alias_value", "alias"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey(
        "advisories.id", ondelete="CASCADE"), nullable=False)
    alias: Mapped[str] = mapped_column(String(128), nullable=False)

    advisory: Mapped[Advisory] = relationship(back_populates="aliases")


class VersionRange(Base):
    __tablename__ = "version_ranges"
    __table_args__ = (
        Index("ix_version_range_advisory_id", "advisory_id"),
        Index("ix_version_range_bounds", "introduced", "fixed"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey(
        "advisories.id", ondelete="CASCADE"), nullable=False)
    introduced: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fixed: Mapped[str | None] = mapped_column(String(128), nullable=True)
    affected_raw: Mapped[str | None] = mapped_column(Text, nullable=True)

    advisory: Mapped[Advisory] = relationship(back_populates="version_ranges")


class Reference(Base):
    __tablename__ = "advisory_references"
    __table_args__ = (
        UniqueConstraint("advisory_id", "url",
                         name="uq_advisory_reference_url"),
        Index("ix_reference_advisory_id", "advisory_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey(
        "advisories.id", ondelete="CASCADE"), nullable=False)
    type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)

    advisory: Mapped[Advisory] = relationship(back_populates="references")
