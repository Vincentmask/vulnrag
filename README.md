# VulnRAG

VulnRAG is a version-aware vulnerability retrieval backend.

Current MVP scope:

1. Ingest OSV vulnerability records.
2. Normalize and store them in PostgreSQL.
3. Parse free-text package queries.
4. Match queried versions against advisory ranges.
5. Return structured JSON output from an API.

## Tech Stack

1. Python 3.11+
2. FastAPI
3. SQLAlchemy
4. PostgreSQL
5. Docker Compose (optional local services)

## Project Layout

1. app: API, ingestion, parser, matcher, database models
2. scripts: utility scripts for DB init and OSV sync
3. tests: unit and API tests
4. data: local OSV sample payloads

## Quick Start

1. Create and activate a virtual environment.
2. Install dependencies.

   pip install -r requirements.txt

3. Copy environment template.

   copy .env.example .env

4. Start PostgreSQL (and pgAdmin if needed).

   docker compose up -d postgres pgadmin

5. Initialize tables.

   python -m scripts.init_db

6. Ingest OSV sample data.

   python -m scripts.sync_osv --file .\data\osv_pypi_1000.json

7. Start API.

   uvicorn app.main:app --reload

## API

1. Health check

   GET /health

2. Query endpoint

   POST /query

   Request body example:

   { "query": "django 1.4 vulnerabilities" }

   Response includes:
   1. parsed_query
   2. resolved_package
   3. matches with advisory id, aliases, severity, affected_status,
      fixed_version, summary

## Query Behavior (Current)

1. Query parser extracts:
   1. package name
   2. optional version
   3. optional severity filter (critical, high, medium, low)
   4. optional recency hint (recent, last year)

2. Version matcher returns:
   1. affected
   2. not_affected
   3. unknown

3. Severity normalization:
   1. Ingestion normalizes to critical, high, medium, low when possible.
   2. Query filtering supports normalized values and legacy text fallback.

4. Summary quality:
   1. If upstream summary exists, it is used.
   2. If missing, deterministic fallback summary is generated.

## Data Workflow Notes

1. Run sync scripts as modules from repo root.

   python -m scripts.sync_osv --file .\data\osv_pypi_1000.json

2. Module invocation avoids import-order issues caused by editor
   auto-organize-imports.

## Tests

Run all tests:

python -m unittest discover -s tests

## Current Limitations

1. Matcher supports semver-like versions only.
2. Ecosystem-specific version semantics are not fully modeled yet.
3. OSV is the only active ingestion source in MVP.

## Next Milestones

1. Incremental sync strategy (modified-time based).
2. Larger ingestion scale and performance checks.
3. Additional data sources after OSV-first pipeline is stable.
