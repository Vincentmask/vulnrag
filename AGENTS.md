# AGENTS.md

## Project

This repository is VulnRAG, a version-aware vulnerability retrieval system for
package and software queries.

## Goal

Build a FastAPI backend that:

- ingests vulnerability data from OSV first
- stores normalized data in PostgreSQL
- supports package and optional version queries
- determines whether a queried version is affected
- returns structured JSON before any natural-language summarization

## Non-goals for MVP

- no frontend
- no multi-agent orchestration
- no NVD ingestion yet
- no LLM summarization until structured retrieval works

## Coding rules

- Use Python 3.11+
- Use FastAPI + SQLAlchemy
- Prefer small focused modules
- Add type hints
- Avoid placeholder implementations
- Do not invent unsupported version-matching logic; mark uncertain cases
  explicitly
- Keep changes minimal and runnable
- Add tests for parsing and version matching

## Workflow rules

- Before making large changes, inspect existing files first
- Prefer incremental commits
- For each task, explain what changed and what remains unfinished
