"""Ongoing regression protection for the Alembic migration itself (see
migrations/versions/7ab42bede884_initial_schema.py): if a future change
to app/db/models.py isn't matched by a new migration, this fails loudly
here rather than the drift going unnoticed until a real deployment's
schema silently disagrees with what the application expects.

Reuses the exact database tests/conftest.py's `_create_tables` fixture
already migrated via a real `alembic upgrade head` - this isn't a second,
separate migration run, just asking Alembic's own comparison engine (the
same one `alembic revision --autogenerate` uses) whether it still sees
anything left to do against the already-migrated schema.
"""

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext

from app.db.base import Base
from app.db.session import engine


def test_migrations_are_in_sync_with_the_models():
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        diff = compare_metadata(context, Base.metadata)

    assert diff == [], (
        "The applied migrations don't match app/db/models.py - a model changed "
        "without a corresponding migration (or vice versa). Generate one with "
        "`alembic revision --autogenerate -m \"<description>\"` and review it "
        f"before committing. Detected difference: {diff}"
    )
