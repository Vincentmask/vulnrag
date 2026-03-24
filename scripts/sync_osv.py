from __future__ import annotations

import argparse
import json
import logging
from typing import Any
from urllib.request import Request, urlopen

try:
    from app.db.session import SessionLocal
    from app.ingestion.osv_ingestor import OsvIngestor
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Unable to import project modules. Run this script as a module from repo root:\n"
        "  python -m scripts.sync_osv --file .\\data\\osv_pypi_1000.json"
    ) from exc


logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync OSV records into the local database")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--file", help="Path to JSON file with OSV data")
    source_group.add_argument(
        "--url", help="URL to JSON payload with OSV data")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args()


def load_json_from_file(file_path: str) -> Any:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_json_from_url(url: str) -> Any:
    request = Request(url, headers={"User-Agent": "vulnrag-osv-sync/0.1"})
    with urlopen(request, timeout=30) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload)


def extract_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    if "id" in payload and "affected" in payload:
        return [payload]

    vulnerabilities = payload.get("vulnerabilities")
    if isinstance(vulnerabilities, list):
        return [item for item in vulnerabilities if isinstance(item, dict)]

    results = payload.get("results")
    if isinstance(results, list):
        flattened: list[dict[str, Any]] = []
        for result in results:
            if not isinstance(result, dict):
                continue
            vulns = result.get("vulns")
            if isinstance(vulns, list):
                flattened.extend(
                    item for item in vulns if isinstance(item, dict))
        return flattened

    return []


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.file:
        payload = load_json_from_file(args.file)
    else:
        payload = load_json_from_url(args.url)

    records = extract_records(payload)
    if not records:
        logger.warning("No OSV records found in input payload")
        return

    ingestor = OsvIngestor(SessionLocal)
    stats = ingestor.ingest_records(records)

    logger.info("OSV sync complete")
    logger.info("Input records: %s", stats["input_records"])
    logger.info("Advisories written: %s", stats["advisories_written"])
    logger.info("Skipped records: %s", stats["skipped_records"])
    logger.info("Partial records: %s", stats["partial_records"])
    logger.info("Errors: %s", stats["errors"])


if __name__ == "__main__":
    main()
