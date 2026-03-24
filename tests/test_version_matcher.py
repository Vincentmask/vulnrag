import unittest

from app.retrieval.version_matcher import (AdvisoryRange,
                                           match_version_against_ranges)


class TestVersionMatcher(unittest.TestCase):
    def test_affected_with_introduced_and_fixed(self) -> None:
        result = match_version_against_ranges(
            "1.2.3",
            [AdvisoryRange(introduced="1.0.0", fixed="2.0.0")],
        )
        self.assertEqual(result.status, "affected")

    def test_not_affected_when_version_before_introduced(self) -> None:
        result = match_version_against_ranges(
            "0.9.9",
            [AdvisoryRange(introduced="1.0.0", fixed="2.0.0")],
        )
        self.assertEqual(result.status, "not_affected")

    def test_not_affected_when_version_at_or_after_fixed(self) -> None:
        result = match_version_against_ranges(
            "2.0.0",
            [AdvisoryRange(introduced="1.0.0", fixed="2.0.0")],
        )
        self.assertEqual(result.status, "not_affected")

    def test_open_upper_bound_is_affected(self) -> None:
        result = match_version_against_ranges(
            "3.1.0",
            [AdvisoryRange(introduced="3.0.0", fixed=None)],
        )
        self.assertEqual(result.status, "affected")

    def test_multiple_ranges_any_match_means_affected(self) -> None:
        result = match_version_against_ranges(
            "2.5.0",
            [
                AdvisoryRange(introduced="1.0.0", fixed="2.0.0"),
                AdvisoryRange(introduced="2.4.0", fixed="3.0.0"),
            ],
        )
        self.assertEqual(result.status, "affected")

    def test_unknown_when_queried_version_is_not_semver_like(self) -> None:
        result = match_version_against_ranges(
            "1:2.3-1ubuntu1",
            [AdvisoryRange(introduced="1.0.0", fixed="2.0.0")],
        )
        self.assertEqual(result.status, "unknown")

    def test_unknown_when_range_boundary_is_not_semver_like(self) -> None:
        result = match_version_against_ranges(
            "1.5.0",
            [AdvisoryRange(introduced="1.0.0", fixed="release-2")],
        )
        self.assertEqual(result.status, "unknown")

    def test_unknown_when_no_ranges(self) -> None:
        result = match_version_against_ranges("1.0.0", [])
        self.assertEqual(result.status, "unknown")


if __name__ == "__main__":
    unittest.main()
