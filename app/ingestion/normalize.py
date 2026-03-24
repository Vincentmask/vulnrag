from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class NormalizedPackage:
    ecosystem: str
    name: str
    normalized_name: str


@dataclass(frozen=True)
class NormalizedVersionRange:
    introduced: str | None
    fixed: str | None
    affected_raw: str | None


@dataclass(frozen=True)
class NormalizedReference:
    type: str | None
    url: str


@dataclass(frozen=True)
class NormalizedAdvisory:
    package: NormalizedPackage
    source: str
    source_advisory_id: str
    summary: str | None
    details: str | None
    severity: str | None
    published_at: datetime | None
    modified_at: datetime | None
    aliases: list[str]
    version_ranges: list[NormalizedVersionRange]
    references: list[NormalizedReference]


@dataclass(frozen=True)
class NormalizationResult:
    advisories: list[NormalizedAdvisory]
    skipped: bool
    messages: list[str]


def normalize_package_name(name: str) -> str:
    return name.strip().lower()


def parse_osv_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


_SEVERITY_WORD_RE = re.compile(
    r"\b(critical|high|medium|moderate|low)\b", re.IGNORECASE)


def _normalize_severity_value(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None

    if candidate == "moderate":
        return "medium"

    if candidate in {"critical", "high", "medium", "low"}:
        return candidate

    word_match = _SEVERITY_WORD_RE.search(candidate)
    if word_match:
        matched = word_match.group(1).lower()
        return "medium" if matched == "moderate" else matched

    # Handle CVSS numeric scores when present (for example: "7.5").
    try:
        numeric_score = float(candidate)
    except ValueError:
        return None

    if numeric_score >= 9.0:
        return "critical"
    if numeric_score >= 7.0:
        return "high"
    if numeric_score >= 4.0:
        return "medium"
    return "low"


def extract_severity(record: dict[str, Any]) -> str | None:
    db_specific = record.get("database_specific")
    if isinstance(db_specific, dict):
        severity = db_specific.get("severity")
        if isinstance(severity, str):
            normalized = _normalize_severity_value(severity)
            if normalized:
                return normalized

    severity_items = record.get("severity")
    if isinstance(severity_items, list) and severity_items:
        for item in severity_items:
            if not isinstance(item, dict):
                continue

            score = item.get("score")
            if isinstance(score, str):
                normalized = _normalize_severity_value(score)
                if normalized:
                    return normalized

            score_type = item.get("type")
            if isinstance(score_type, str):
                normalized = _normalize_severity_value(score_type)
                if normalized:
                    return normalized

    return None


def build_ranges(affected_item: dict[str, Any]) -> list[NormalizedVersionRange]:
    affected_raw = json.dumps(
        affected_item, separators=(",", ":"), ensure_ascii=True)
    ranges = affected_item.get("ranges")
    normalized_ranges: list[NormalizedVersionRange] = []

    if not isinstance(ranges, list):
        versions = affected_item.get("versions")
        if isinstance(versions, list) and versions:
            normalized_ranges.append(
                NormalizedVersionRange(
                    introduced=None, fixed=None, affected_raw=affected_raw)
            )
        return normalized_ranges

    for range_item in ranges:
        if not isinstance(range_item, dict):
            continue

        events = range_item.get("events")
        if not isinstance(events, list):
            continue

        current_introduced: str | None = None
        found_segment = False

        for event in events:
            if not isinstance(event, dict):
                continue

            introduced = event.get("introduced")
            fixed = event.get("fixed")

            if isinstance(introduced, str) and introduced.strip():
                current_introduced = introduced.strip()

            if isinstance(fixed, str) and fixed.strip():
                normalized_ranges.append(
                    NormalizedVersionRange(
                        introduced=current_introduced,
                        fixed=fixed.strip(),
                        affected_raw=affected_raw,
                    )
                )
                found_segment = True
                current_introduced = None

        if current_introduced is not None:
            normalized_ranges.append(
                NormalizedVersionRange(
                    introduced=current_introduced,
                    fixed=None,
                    affected_raw=affected_raw,
                )
            )
            found_segment = True

        if not found_segment:
            normalized_ranges.append(
                NormalizedVersionRange(
                    introduced=None, fixed=None, affected_raw=affected_raw)
            )

    return normalized_ranges


def build_fallback_summary(
    source_advisory_id: str,
    package_name: str,
    severity: str | None,
    fixed_version: str | None,
    aliases: list[str],
) -> str:
    alias_text = aliases[0] if aliases else source_advisory_id
    if fixed_version and severity:
        return f"{package_name} advisory {alias_text} ({severity}), fixed in {fixed_version}."
    if fixed_version:
        return f"{package_name} advisory {alias_text}, fixed in {fixed_version}."
    if severity:
        return f"{package_name} advisory {alias_text} with severity {severity}."
    return f"{package_name} advisory {alias_text}."


def normalize_osv_record(record: dict[str, Any]) -> NormalizationResult:
    messages: list[str] = []

    source_advisory_id = record.get("id")
    if not isinstance(source_advisory_id, str) or not source_advisory_id.strip():
        return NormalizationResult(advisories=[], skipped=True, messages=["missing advisory id"])

    affected = record.get("affected")
    if not isinstance(affected, list) or not affected:
        return NormalizationResult(
            advisories=[],
            skipped=True,
            messages=[f"{source_advisory_id}: no affected packages"],
        )

    advisories: list[NormalizedAdvisory] = []
    severity = extract_severity(record)
    published_at = parse_osv_timestamp(record.get("published"))
    modified_at = parse_osv_timestamp(record.get("modified"))
    summary = record.get("summary") if isinstance(
        record.get("summary"), str) else None
    details = record.get("details") if isinstance(
        record.get("details"), str) else None

    aliases_raw = record.get("aliases")
    aliases: list[str] = []
    if isinstance(aliases_raw, list):
        seen_aliases: set[str] = set()
        for alias in aliases_raw:
            if not isinstance(alias, str):
                continue
            cleaned = alias.strip()
            if not cleaned or cleaned in seen_aliases:
                continue
            seen_aliases.add(cleaned)
            aliases.append(cleaned)

    references_raw = record.get("references")
    references: list[NormalizedReference] = []
    if isinstance(references_raw, list):
        seen_reference_urls: set[str] = set()
        for ref in references_raw:
            if not isinstance(ref, dict):
                continue
            url = ref.get("url")
            if not isinstance(url, str) or not url.strip():
                continue
            cleaned_url = url.strip()
            if cleaned_url in seen_reference_urls:
                continue
            seen_reference_urls.add(cleaned_url)
            ref_type = ref.get("type")
            references.append(
                NormalizedReference(
                    type=ref_type.strip() if isinstance(ref_type, str) and ref_type.strip() else None,
                    url=cleaned_url,
                )
            )

    for affected_item in affected:
        if not isinstance(affected_item, dict):
            messages.append(
                f"{source_advisory_id}: skipped malformed affected entry")
            continue

        package_obj = affected_item.get("package")
        if not isinstance(package_obj, dict):
            messages.append(
                f"{source_advisory_id}: skipped affected entry without package object")
            continue

        ecosystem = package_obj.get("ecosystem")
        name = package_obj.get("name")
        if not isinstance(ecosystem, str) or not ecosystem.strip() or not isinstance(name, str) or not name.strip():
            messages.append(
                f"{source_advisory_id}: skipped affected entry missing package ecosystem/name")
            continue

        package = NormalizedPackage(
            ecosystem=ecosystem.strip(),
            name=name.strip(),
            normalized_name=normalize_package_name(name),
        )

        version_ranges = build_ranges(affected_item)
        first_fixed_version = next(
            (version_range.fixed for version_range in version_ranges if version_range.fixed),
            None,
        )
        normalized_summary = summary.strip() if isinstance(
            summary, str) and summary.strip() else None
        if normalized_summary is None:
            normalized_summary = build_fallback_summary(
                source_advisory_id=source_advisory_id.strip(),
                package_name=package.name,
                severity=severity,
                fixed_version=first_fixed_version,
                aliases=aliases,
            )

        advisories.append(
            NormalizedAdvisory(
                package=package,
                source="osv",
                source_advisory_id=source_advisory_id.strip(),
                summary=normalized_summary,
                details=details,
                severity=severity,
                published_at=published_at,
                modified_at=modified_at,
                aliases=aliases,
                version_ranges=version_ranges,
                references=references,
            )
        )

    if not advisories:
        return NormalizationResult(
            advisories=[],
            skipped=True,
            messages=messages or [
                f"{source_advisory_id}: no valid package entries"],
        )

    return NormalizationResult(advisories=advisories, skipped=False, messages=messages)
