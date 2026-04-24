"""Database reset: drops all tables, recreates schema, and re-seeds.

Mirrors DVWA's setup.php pattern. The database is ephemeral; challenge
progress persists in the signed session cookie.
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect

from app.db.database import Base, SessionLocal, engine
from app.db.seed import seed_all

logger = logging.getLogger(__name__)


def reset_database() -> None:
    """Drop all tables, recreate schema, and seed with default data."""
    logger.info("Dropping all tables...")
    Base.metadata.drop_all(bind=engine)

    logger.info("Creating all tables...")
    Base.metadata.create_all(bind=engine)

    logger.info("Seeding database...")
    seed_all()

    logger.info("Database reset complete.")


def _schema_drifted() -> bool:
    """Return True if any existing table is missing columns defined on its model.

    DVS has no migrations by design. When the model gains a column, an older
    SQLite file on disk silently stays on the old schema and the next query
    crashes. Detect drift by comparing reflected columns to declared columns.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        reflected = {c["name"] for c in inspector.get_columns(table.name)}
        declared = {c.name for c in table.columns}
        if declared - reflected:
            logger.warning(
                "Schema drift on %s: missing %s; rebuilding.",
                table.name,
                sorted(declared - reflected),
            )
            return True
    return False


def init_database() -> None:
    """Create tables if they don't exist and seed if empty.

    Called on application startup. Non-destructive: only creates missing
    tables and seeds if the users table is empty. Falls back to a full
    reset when schema drift is detected (model added columns since the
    on-disk DB was created).
    """
    if _schema_drifted():
        reset_database()
        return

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        from app.models.user import User

        user_count = db.query(User).count()
        if user_count == 0:
            logger.info("Empty database detected, seeding...")
            from app.db.seed import seed_challenges, seed_users

            seed_users(db)
            seed_challenges(db)
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    reset_database()
