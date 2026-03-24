from __future__ import annotations

import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import Advisory, Package
from app.ingestion.osv_ingestor import OsvIngestor
from app.main import app, get_db


class TestIngestionIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.SessionLocal = sessionmaker(
            bind=self.engine, autocommit=False, autoflush=False)
        Base.metadata.create_all(self.engine)

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

    def test_ingest_then_query_end_to_end(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        records = [
            {
                "id": "OSV-E2E-1",
                "published": now,
                "modified": now,
                "severity": [{"type": "CVSS_V3", "score": "7.8"}],
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo-pkg"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "2.0.0"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]

        ingestor = OsvIngestor(self.SessionLocal)
        stats = ingestor.ingest_records(records)
        self.assertEqual(stats["errors"], 0)
        self.assertEqual(stats["advisories_written"], 1)

        response = self.client.post(
            "/query",
            json={"query": "for demo-pkg 1.5.0 severity high"},
        )
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertIsNotNone(payload["resolved_package"])
        self.assertEqual(payload["resolved_package"]["normalized_name"], "demo-pkg")
        self.assertEqual(len(payload["matches"]), 1)

        match = payload["matches"][0]
        self.assertEqual(match["source_advisory_id"], "OSV-E2E-1")
        self.assertEqual(match["severity"], "high")
        self.assertEqual(match["affected_status"], "affected")
        self.assertEqual(match["fixed_version"], "2.0.0")

    def test_ingestion_is_idempotent_for_same_advisory(self) -> None:
        record = {
            "id": "OSV-E2E-IDEMPOTENT",
            "modified": datetime.now(timezone.utc).isoformat(),
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "idempotent-pkg"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
                        }
                    ],
                }
            ],
        }

        ingestor = OsvIngestor(self.SessionLocal)
        ingestor.ingest_records([record])
        ingestor.ingest_records([record])

        with self.SessionLocal() as session:
            package = session.scalar(
                select(Package).where(Package.normalized_name == "idempotent-pkg")
            )
            self.assertIsNotNone(package)
            advisory_count = session.query(Advisory).filter(
                Advisory.package_id == package.id,
                Advisory.source == "osv",
                Advisory.source_advisory_id == "OSV-E2E-IDEMPOTENT",
            ).count()
            self.assertEqual(advisory_count, 1)


if __name__ == "__main__":
    unittest.main()
