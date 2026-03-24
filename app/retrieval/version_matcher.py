from __future__ import annotations

"""Version matching for package vulnerability lookup.

This module intentionally supports only common semver-like versions.

Current limitations:
- Only semver-like strings are compared (for example: 1.2.3, v1.2.3, 1.2.3-beta.1).
- Ecosystem-specific version schemes (Debian, Maven qualifiers, rpm, etc.) are not supported.
- Complex OSV event semantics beyond introduced/fixed are not modeled in this first version.
- Any unparsable version or range boundary returns an explicit "unknown" result.
"""

import re
from dataclasses import dataclass
from typing import Literal, Sequence

MatchStatus = Literal["affected", "not_affected", "unknown"]

_SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@dataclass(frozen=True)
class AdvisoryRange:
    """Normalized advisory interval.

    - introduced: inclusive lower bound, if present.
    - fixed: exclusive upper bound, if present.
    """

    introduced: str | None
    fixed: str | None


@dataclass(frozen=True)
class VersionMatchResult:
    """Structured version matching result.

    Fields:
    - status: "affected", "not_affected", or "unknown".
    - reason: Human-readable explanation for the decision.
    - matched_range: Range that matched when status is "affected", else None.
    """

    status: MatchStatus
    reason: str
    matched_range: AdvisoryRange | None = None


@dataclass(frozen=True)
class _SemverLike:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...]


def match_version_against_ranges(
    package_version: str,
    ranges: Sequence[AdvisoryRange],
) -> VersionMatchResult:
    """Match a queried package version against normalized advisory ranges."""

    parsed_version = _parse_semver_like(package_version)
    if parsed_version is None:
        return VersionMatchResult(
            status="unknown",
            reason="Queried version is not semver-like; matcher cannot determine impact.",
        )

    if not ranges:
        return VersionMatchResult(
            status="unknown",
            reason="No advisory ranges provided.",
        )

    has_unknown_range = False
    comparable_ranges = 0

    for advisory_range in ranges:
        range_eval = _evaluate_range(parsed_version, advisory_range)
        if range_eval == "affected":
            return VersionMatchResult(
                status="affected",
                reason="Version falls within an affected introduced/fixed range.",
                matched_range=advisory_range,
            )
        if range_eval == "not_affected":
            comparable_ranges += 1
            continue

        has_unknown_range = True

    if has_unknown_range:
        return VersionMatchResult(
            status="unknown",
            reason="At least one advisory range is not semver-comparable, so result is uncertain.",
        )

    if comparable_ranges > 0:
        return VersionMatchResult(
            status="not_affected",
            reason="Version is outside all semver-comparable advisory ranges.",
        )

    return VersionMatchResult(
        status="unknown",
        reason="No comparable advisory ranges were available.",
    )


def _evaluate_range(version: _SemverLike, advisory_range: AdvisoryRange) -> MatchStatus:
    introduced_raw = advisory_range.introduced
    fixed_raw = advisory_range.fixed

    if introduced_raw is None and fixed_raw is None:
        return "unknown"

    introduced = _parse_semver_like(introduced_raw) if introduced_raw else None
    fixed = _parse_semver_like(fixed_raw) if fixed_raw else None

    if introduced_raw and introduced is None:
        return "unknown"
    if fixed_raw and fixed is None:
        return "unknown"

    if introduced is not None and _compare_semver(version, introduced) < 0:
        return "not_affected"

    if fixed is not None and _compare_semver(version, fixed) >= 0:
        return "not_affected"

    return "affected"


def _parse_semver_like(value: str | None) -> _SemverLike | None:
    if value is None:
        return None

    text = value.strip()
    if not text:
        return None

    match = _SEMVER_RE.match(text)
    if not match:
        return None

    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)
    prerelease_raw = match.group(4)
    prerelease = tuple(prerelease_raw.split(
        ".")) if prerelease_raw else tuple()

    return _SemverLike(major=major, minor=minor, patch=patch, prerelease=prerelease)


def _compare_semver(left: _SemverLike, right: _SemverLike) -> int:
    left_core = (left.major, left.minor, left.patch)
    right_core = (right.major, right.minor, right.patch)

    if left_core < right_core:
        return -1
    if left_core > right_core:
        return 1

    return _compare_prerelease(left.prerelease, right.prerelease)


def _compare_prerelease(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    if not left and not right:
        return 0
    if not left:
        return 1
    if not right:
        return -1

    max_len = max(len(left), len(right))
    for i in range(max_len):
        if i >= len(left):
            return -1
        if i >= len(right):
            return 1

        lpart = left[i]
        rpart = right[i]

        if lpart == rpart:
            continue

        lnum = lpart.isdigit()
        rnum = rpart.isdigit()

        if lnum and rnum:
            li = int(lpart)
            ri = int(rpart)
            if li < ri:
                return -1
            if li > ri:
                return 1
            continue

        if lnum and not rnum:
            return -1
        if not lnum and rnum:
            return 1

        if lpart < rpart:
            return -1
        if lpart > rpart:
            return 1

    return 0
