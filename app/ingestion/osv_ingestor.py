from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import (Advisory, AdvisoryAlias, Package, Reference,
                           VersionRange)
from app.ingestion.normalize import NormalizedAdvisory, normalize_osv_record

logger = logging.getLogger(__name__)


class OsvIngestor:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory

    def ingest_records(self, records: list[dict[str, Any]]) -> dict[str, int]:
        stats = {
            "input_records": len(records),
            "advisories_written": 0,
            "skipped_records": 0,
            "partial_records": 0,
            "errors": 0,
        }

        with self.session_factory() as session:
            for index, record in enumerate(records, start=1):
                try:
                    result = normalize_osv_record(record)

                    if result.messages:
                        stats["partial_records"] += 1
                        for message in result.messages:
                            logger.warning("Record %s: %s", index, message)

                    if result.skipped:
                        stats["skipped_records"] += 1
                        continue

                    for normalized in result.advisories:
                        self._upsert_advisory(session, normalized)
                        stats["advisories_written"] += 1

                    session.commit()
                except Exception as exc:
                    stats["errors"] += 1
                    session.rollback()
                    logger.exception(
                        "Failed to ingest record %s: %s", index, exc)

        return stats

    def _upsert_advisory(self, session: Session, data: NormalizedAdvisory) -> None:
        package = self._get_or_create_package(session, data)

        advisory = session.scalar(
            select(Advisory).where(
                Advisory.package_id == package.id,
                Advisory.source == data.source,
                Advisory.source_advisory_id == data.source_advisory_id,
            )
        )
        if advisory is None:
            advisory = Advisory(
                package_id=package.id,
                source=data.source,
                source_advisory_id=data.source_advisory_id,
            )
            session.add(advisory)
            session.flush()

        advisory.summary = data.summary
        advisory.details = data.details
        advisory.severity = data.severity
        advisory.published_at = data.published_at
        advisory.modified_at = data.modified_at

        session.query(AdvisoryAlias).filter(
            AdvisoryAlias.advisory_id == advisory.id).delete()
        session.query(VersionRange).filter(
            VersionRange.advisory_id == advisory.id).delete()
        session.query(Reference).filter(
            Reference.advisory_id == advisory.id).delete()

        for alias in data.aliases:
            session.add(AdvisoryAlias(advisory_id=advisory.id, alias=alias))

        for version_range in data.version_ranges:
            session.add(
                VersionRange(
                    advisory_id=advisory.id,
                    introduced=version_range.introduced,
                    fixed=version_range.fixed,
                    affected_raw=version_range.affected_raw,
                )
            )

        for reference in data.references:
            session.add(
                Reference(
                    advisory_id=advisory.id,
                    type=reference.type,
                    url=reference.url,
                )
            )

        session.flush()

    def _get_or_create_package(self, session: Session, data: NormalizedAdvisory) -> Package:
        package = session.scalar(
            select(Package).where(
                Package.ecosystem == data.package.ecosystem,
                Package.normalized_name == data.package.normalized_name,
            )
        )
        if package is None:
            package = Package(
                ecosystem=data.package.ecosystem,
                name=data.package.name,
                normalized_name=data.package.normalized_name,
            )
            session.add(package)
            session.flush()
            return package

        if package.name != data.package.name:
            package.name = data.package.name

        return package
