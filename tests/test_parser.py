import unittest

from app.retrieval.parser import parse_query


class TestQueryParser(unittest.TestCase):
    def test_extracts_package_and_version_from_at_format(self) -> None:
        parsed = parse_query("check lodash@4.17.21 vulnerabilities")
        self.assertEqual(parsed.package_name, "lodash")
        self.assertEqual(parsed.version, "4.17.21")

    def test_extracts_package_version_severity_and_last_year(self) -> None:
        parsed = parse_query(
            "is requests 2.31.0 high severity in the last year")
        self.assertEqual(parsed.package_name, "requests")
        self.assertEqual(parsed.version, "2.31.0")
        self.assertEqual(parsed.severity, "high")
        self.assertEqual(parsed.recent_hint, "last_year")

    def test_extracts_explicit_package_clause(self) -> None:
        parsed = parse_query("lookup package django severity:critical recent")
        self.assertEqual(parsed.package_name, "django")
        self.assertIsNone(parsed.version)
        self.assertEqual(parsed.severity, "critical")
        self.assertEqual(parsed.recent_hint, "recent")

    def test_extracts_version_with_v_prefix(self) -> None:
        parsed = parse_query("for urllib3 v1.26.18")
        self.assertEqual(parsed.package_name, "urllib3")
        self.assertEqual(parsed.version, "1.26.18")

    def test_handles_query_without_package(self) -> None:
        parsed = parse_query("recent vulnerabilities with severity low")
        self.assertIsNone(parsed.package_name)
        self.assertIsNone(parsed.version)
        self.assertEqual(parsed.severity, "low")
        self.assertEqual(parsed.recent_hint, "recent")


if __name__ == "__main__":
    unittest.main()
