from __future__ import annotations

import unittest

from app.ingestion.normalize import build_fallback_summary, extract_severity


class TestNormalizeSeverity(unittest.TestCase):
    def test_prefers_database_specific_severity(self) -> None:
        record = {
            "database_specific": {"severity": "HIGH"},
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}
            ],
        }
        self.assertEqual(extract_severity(record), "high")

    def test_normalizes_textual_moderate_to_medium(self) -> None:
        record = {"database_specific": {"severity": "moderate"}}
        self.assertEqual(extract_severity(record), "medium")

    def test_maps_numeric_cvss_score(self) -> None:
        record = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        self.assertEqual(extract_severity(record), "high")

    def test_returns_none_for_unrecognized_values(self) -> None:
        record = {"severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}]}
        self.assertIsNone(extract_severity(record))

    def test_build_fallback_summary_with_fixed_and_severity(self) -> None:
        summary = build_fallback_summary(
            source_advisory_id="GHSA-1234",
            package_name="django",
            severity="high",
            fixed_version="4.2.1",
            aliases=["CVE-2026-0001"],
        )
        self.assertEqual(
            summary, "django advisory CVE-2026-0001 (high), fixed in 4.2.1.")

    def test_build_fallback_summary_without_optional_fields(self) -> None:
        summary = build_fallback_summary(
            source_advisory_id="GHSA-1234",
            package_name="django",
            severity=None,
            fixed_version=None,
            aliases=[],
        )
        self.assertEqual(summary, "django advisory GHSA-1234.")


if __name__ == "__main__":
    unittest.main()
