from __future__ import annotations

import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import Advisory, AdvisoryAlias, Package, VersionRange
from app.main import MAX_QUERY_MATCHES, app, get_db


class TestQueryApi(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.SessionLocal = sessionmaker(
            bind=self.engine, autocommit=False, autoflush=False)
        Base.metadata.create_all(self.engine)
        self._seed_data()

        def override_get_db():
            session: Session = self.SessionLocal()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    def _seed_data(self) -> None:
        with self.SessionLocal() as session:
            package = Package(ecosystem="PyPI", name="requests",
                              normalized_name="requests")
            session.add(package)
            session.flush()

            advisory = Advisory(
                package_id=package.id,
                source="osv",
                source_advisory_id="OSV-TEST-1",
                summary="Demo advisory",
                severity="high",
                modified_at=datetime.now(timezone.utc),
            )
            session.add(advisory)
            session.flush()

            session.add(AdvisoryAlias(
                advisory_id=advisory.id, alias="CVE-2099-0001"))
            session.add(
                VersionRange(
                    advisory_id=advisory.id,
                    introduced="1.0.0",
                    fixed="2.0.0",
                    affected_raw='{"demo":true}',
                )
            )
            session.commit()

    def test_query_returns_structured_matches(self) -> None:
        response = self.client.post(
            "/query",
            json={"query": "check requests 1.2.3 severity high recent"},
        )
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertIn("parsed_query", payload)
        self.assertIn("resolved_package", payload)
        self.assertIn("matches", payload)

        self.assertEqual(payload["parsed_query"]["package_name"], "requests")
        self.assertEqual(payload["parsed_query"]["version"], "1.2.3")
        self.assertEqual(payload["parsed_query"]["severity"], "high")
        self.assertEqual(payload["parsed_query"]["recent_hint"], "recent")

        self.assertIsNotNone(payload["resolved_package"])
        self.assertEqual(payload["resolved_package"]
                         ["normalized_name"], "requests")

        self.assertGreaterEqual(len(payload["matches"]), 1)
        match = payload["matches"][0]
        self.assertEqual(match["source_advisory_id"], "OSV-TEST-1")
        self.assertEqual(match["aliases"], ["CVE-2099-0001"])
        self.assertEqual(match["severity"], "high")
        self.assertEqual(match["affected_status"], "affected")
        self.assertEqual(match["fixed_version"], "2.0.0")
        self.assertEqual(match["summary"], "Demo advisory")

    def test_query_falls_back_when_summary_missing(self) -> None:
        with self.SessionLocal() as session:
            advisory = session.scalar(
                session.query(Advisory).filter(
                    Advisory.source_advisory_id == "OSV-TEST-1").statement
            )
            assert advisory is not None
            advisory.summary = None
            session.commit()

        response = self.client.post(
            "/query",
            json={"query": "check requests 1.2.3"},
        )
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertGreaterEqual(len(payload["matches"]), 1)
        summary = payload["matches"][0]["summary"]
        self.assertIsNotNone(summary)
        self.assertIn("requests advisory", summary)

    def test_query_unknown_package_returns_empty(self) -> None:
        response = self.client.post(
            "/query",
            json={"query": "check package-that-does-not-exist 1.0.0"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIsNone(payload["resolved_package"])
        self.assertEqual(payload["matches"], [])

    def test_query_result_count_is_limited(self) -> None:
        with self.SessionLocal() as session:
            package = session.scalar(
                session.query(Package).filter(
                    Package.normalized_name == "requests").statement
            )
            assert package is not None

            for index in range(MAX_QUERY_MATCHES + 25):
                advisory = Advisory(
                    package_id=package.id,
                    source="osv",
                    source_advisory_id=f"OSV-LIMIT-{index}",
                    summary=f"Limit advisory {index}",
                    severity="high",
                    modified_at=datetime.now(timezone.utc),
                )
                session.add(advisory)

            session.commit()

        response = self.client.post(
            "/query",
            json={"query": "check requests"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["matches"]), MAX_QUERY_MATCHES)


if __name__ == "__main__":
    unittest.main()
