from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# Importing app.db.models (not just app.db.base) is required, not
# incidental: it's what registers AuditEvent/IdempotencyKey on
# Base.metadata at all. Without this import, target_metadata below would
# be an empty MetaData object and `alembic revision --autogenerate` would
# see every existing table as something to drop.
from app.core.config import settings
from app.db import models  # noqa: F401
from app.db.base import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Reuse the application's own Settings (see alembic.ini's comment on
# sqlalchemy.url) rather than a second, separately-maintained connection
# string - respects the same .env/.env.test/ENV_FILE selection the app
# and test suite already use (see README.md).
config.set_main_option("sqlalchemy.url", settings.database_url)

# Interpret the config file for Python logging.
# This line sets up loggers basically.
#
# disable_existing_loggers=False is a deliberate change from Alembic's
# generated default (True): alembic.ini only lists root/sqlalchemy/alembic
# in its [loggers] section, and fileConfig()'s default behavior disables
# every *other* logger that already exists at the time it runs - which
# would silently and permanently disable this application's own
# "audit_log_service" logger (app/core/logging_config.py) the moment
# Alembic runs in-process (e.g. tests/conftest.py invoking
# `alembic.command.upgrade` programmatically, in the same process as the
# rest of the test suite). Discovered exactly this way: security-event
# log assertions started failing suite-wide the moment tests switched
# from Base.metadata.create_all() to running real migrations.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
