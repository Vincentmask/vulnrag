# AGENTS

This file documents agent roles and repository conventions.

## Roles

- Planner: Breaks tasks into small, testable steps.
- Builder: Implements features in app/.
- Reviewer: Verifies correctness, style, and test coverage.

## Working Agreements

- Keep code changes scoped and atomic.
- Add or update tests in tests/ for behavior changes.
- Document architecture and decisions in docs/.
- Keep scripts in scripts/ idempotent where possible.
