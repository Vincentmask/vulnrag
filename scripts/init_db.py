from __future__ import annotations

try:
    from app.db.base import Base
    from app.db.session import engine
    from app.db import models  # noqa: F401
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Unable to import project modules. Run this script as a module from repo root:\n"
        "  python -m scripts.init_db"
    ) from exc


def main() -> None:
    Base.metadata.create_all(bind=engine)
    print("Database tables created.")


if __name__ == "__main__":
    main()
