from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

Severity = Literal["critical", "high", "medium", "low"]
RecentHint = Literal["recent", "last_year"]

_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?$")
_PACKAGE_AT_VERSION_RE = re.compile(
    r"\b([A-Za-z0-9_.-]+)@([0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.-]+)?)\b"
)
_EXPLICIT_PACKAGE_RE = re.compile(
    r"\b(?:package|pkg|for)\s+([A-Za-z0-9_.-]+)(?:\s+v?([0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.-]+)?))?\b",
    re.IGNORECASE,
)

_STOPWORDS = {
    "check",
    "is",
    "are",
    "vulnerable",
    "vulnerability",
    "vulnerabilities",
    "show",
    "find",
    "lookup",
    "look",
    "up",
    "for",
    "package",
    "pkg",
    "severity",
    "with",
    "in",
    "the",
    "last",
    "year",
    "recent",
    "critical",
    "high",
    "medium",
    "low",
}


@dataclass(frozen=True)
class ParsedQuery:
    """Structured parse result for package vulnerability lookup.

    Fields:
    - raw_query: Original user input.
    - package_name: Extracted package name, if present.
    - version: Extracted package version, if present.
    - severity: Extracted severity filter (critical/high/medium/low), if present.
    - recent_hint: Time hint extracted from input.
      - "last_year": user mentioned "last year".
      - "recent": user mentioned "recent".
    """

    raw_query: str
    package_name: str | None
    version: str | None
    severity: Severity | None
    recent_hint: RecentHint | None


def parse_query(query: str) -> ParsedQuery:
    text = (query or "").strip()
    lowered = text.lower()

    severity = _extract_severity(lowered)
    recent_hint = _extract_recent_hint(lowered)
    package_name, version = _extract_package_and_version(text)

    return ParsedQuery(
        raw_query=text,
        package_name=package_name,
        version=version,
        severity=severity,
        recent_hint=recent_hint,
    )


def _extract_severity(lowered_query: str) -> Severity | None:
    match = re.search(
        r"\b(?:severity|sev)\s*(?:is|=|:)?\s*(critical|high|medium|low)\b", lowered_query)
    if match:
        return match.group(1)  # type: ignore[return-value]

    match = re.search(
        r"\b(critical|high|medium|low)\s+severity\b", lowered_query)
    if match:
        return match.group(1)  # type: ignore[return-value]

    return None


def _extract_recent_hint(lowered_query: str) -> RecentHint | None:
    if "last year" in lowered_query:
        return "last_year"
    if "recent" in lowered_query:
        return "recent"
    return None


def _extract_package_and_version(query: str) -> tuple[str | None, str | None]:
    match = _PACKAGE_AT_VERSION_RE.search(query)
    if match:
        return match.group(1), match.group(2)

    match = _EXPLICIT_PACKAGE_RE.search(query)
    if match:
        package_name = match.group(1)
        version = _normalize_version(
            match.group(2)) if match.group(2) else None
        return package_name, version

    tokens = re.findall(r"[A-Za-z0-9_.-]+", query)
    package_name: str | None = None
    version: str | None = None

    for idx, token in enumerate(tokens):
        lowered = token.lower()
        if lowered in _STOPWORDS:
            continue

        if _is_version_token(token):
            if idx > 0 and package_name is None:
                prev = tokens[idx - 1]
                if prev.lower() not in _STOPWORDS and not _is_version_token(prev):
                    package_name = prev
                    version = _normalize_version(token)
            continue

        if package_name is None:
            package_name = token
            if idx + 1 < len(tokens) and _is_version_token(tokens[idx + 1]):
                version = _normalize_version(tokens[idx + 1])
            break

    return package_name, version


def _is_version_token(token: str) -> bool:
    return bool(_VERSION_RE.match(token))


def _normalize_version(token: str | None) -> str | None:
    if token is None:
        return None
    return token[1:] if token.startswith("v") else token
