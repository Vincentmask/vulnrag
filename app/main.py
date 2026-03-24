from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Generator

from fastapi import Depends, FastAPI
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.db.models import Advisory, Package
from app.db.session import SessionLocal
from app.ingestion.normalize import normalize_package_name
from app.retrieval.parser import ParsedQuery, parse_query
from app.retrieval.version_matcher import (AdvisoryRange,
                                           match_version_against_ranges)

settings = get_settings()
app = FastAPI(title=settings.app_name)
MAX_QUERY_MATCHES = 1000


class QueryRequest(BaseModel):
    query: str


class ParsedQueryResponse(BaseModel):
    raw_query: str
    package_name: str | None
    version: str | None
    severity: str | None
    recent_hint: str | None


class ResolvedPackageResponse(BaseModel):
    id: int
    ecosystem: str
    name: str
    normalized_name: str


class AdvisoryMatchResponse(BaseModel):
    advisory_id: int
    source: str
    source_advisory_id: str
    aliases: list[str]
    severity: str | None
    affected_status: str
    fixed_version: str | None
    summary: str | None


class QueryResponse(BaseModel):
    parsed_query: ParsedQueryResponse
    resolved_package: ResolvedPackageResponse | None
    matches: list[AdvisoryMatchResponse]


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/query", response_model=QueryResponse)
def query_vulnerabilities(payload: QueryRequest, db: Session = Depends(get_db)) -> QueryResponse:
    parsed = parse_query(payload.query)

    parsed_response = ParsedQueryResponse(
        raw_query=parsed.raw_query,
        package_name=parsed.package_name,
        version=parsed.version,
        severity=parsed.severity,
        recent_hint=parsed.recent_hint,
    )

    if not parsed.package_name:
        return QueryResponse(parsed_query=parsed_response, resolved_package=None, matches=[])

    normalized = normalize_package_name(parsed.package_name)
    package = db.scalar(
        select(Package)
        .where(Package.normalized_name == normalized)
        .order_by(Package.id.asc())
        .limit(1)
    )

    if package is None:
        return QueryResponse(parsed_query=parsed_response, resolved_package=None, matches=[])

    advisory_stmt = (
        select(Advisory)
        .where(Advisory.package_id == package.id)
        .options(
            selectinload(Advisory.aliases),
            selectinload(Advisory.version_ranges),
        )
        .order_by(Advisory.id.desc())
        .limit(MAX_QUERY_MATCHES)
    )

    if parsed.severity:
        advisory_stmt = advisory_stmt.where(
            or_(
                Advisory.severity == parsed.severity,
                Advisory.severity.ilike(f"%{parsed.severity}%"),
            )
        )

    cutoff = _recent_cutoff(parsed)
    if cutoff is not None:
        advisory_stmt = advisory_stmt.where(Advisory.modified_at >= cutoff)

    advisories = db.scalars(advisory_stmt).all()
    matches: list[AdvisoryMatchResponse] = []
    for advisory in advisories:
        ranges = [
            AdvisoryRange(introduced=version_range.introduced,
                          fixed=version_range.fixed)
            for version_range in advisory.version_ranges
        ]

        affected_status = "unknown"
        if parsed.version:
            affected_status = match_version_against_ranges(
                parsed.version, ranges).status

        matches.append(
            AdvisoryMatchResponse(
                advisory_id=advisory.id,
                source=advisory.source,
                source_advisory_id=advisory.source_advisory_id,
                aliases=[alias.alias for alias in advisory.aliases],
                severity=advisory.severity,
                affected_status=affected_status,
                fixed_version=_first_fixed_version(advisory),
                summary=_display_summary(advisory, package.name),
            )
        )

    return QueryResponse(
        parsed_query=parsed_response,
        resolved_package=ResolvedPackageResponse(
            id=package.id,
            ecosystem=package.ecosystem,
            name=package.name,
            normalized_name=package.normalized_name,
        ),
        matches=matches,
    )


def _recent_cutoff(parsed: ParsedQuery) -> datetime | None:
    if parsed.recent_hint == "last_year":
        return datetime.now(timezone.utc) - timedelta(days=365)
    if parsed.recent_hint == "recent":
        return datetime.now(timezone.utc) - timedelta(days=180)
    return None


def _first_fixed_version(advisory: Advisory) -> str | None:
    for version_range in advisory.version_ranges:
        if version_range.fixed:
            return version_range.fixed
    return None


def _display_summary(advisory: Advisory, package_name: str) -> str:
    if advisory.summary and advisory.summary.strip():
        return advisory.summary.strip()

    first_alias = advisory.aliases[0].alias if advisory.aliases else advisory.source_advisory_id
    fixed_version = _first_fixed_version(advisory)

    if fixed_version and advisory.severity:
        return f"{package_name} advisory {first_alias} ({advisory.severity}), fixed in {fixed_version}."
    if fixed_version:
        return f"{package_name} advisory {first_alias}, fixed in {fixed_version}."
    if advisory.severity:
        return f"{package_name} advisory {first_alias} with severity {advisory.severity}."
    return f"{package_name} advisory {first_alias}."
