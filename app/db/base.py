from sqlalchemy.orm import declarative_base

# Common declarative base. Future SQLAlchemy models (e.g. the audit event
# model) should inherit from this so they share metadata and can be created
# via the same engine.
Base = declarative_base()
