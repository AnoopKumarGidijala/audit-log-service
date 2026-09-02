# Audit Log Service

A tamper-evident audit log service that records application and system events in a way that allows their integrity to be independently verified after the fact.

## Setup

Prerequisites: Docker, and Python 3 with a virtual environment.

1. **Configure the environment.** Copy `.env.example` to `.env` and adjust values for your machine (generate a real `SECRET_KEY`, pick your own local Postgres credentials, etc. - see the comments in the file itself).

   ```bash
   cp .env.example .env
   ```

2. **Start the development database:**

   ```bash
   docker compose up -d
   ```

3. **Install the pinned Python dependencies**, ideally into a virtual environment:

   ```bash
   pip install -r requirements.txt
   ```

   Versions are pinned to exactly what this project is tested against (see the comment at the top of `requirements.txt`), so this install is reproducible rather than picking up whatever the latest compatible release happens to be on a given day.

4. **Apply database migrations.** The application no longer creates tables automatically on startup - schema changes are applied explicitly via [Alembic](https://alembic.sqlalchemy.org/), the standard SQLAlchemy migration tool:

   ```bash
   alembic upgrade head
   ```

   This is the same command a fresh environment (a new developer's machine, a new deployment) runs to go from an empty database to the current schema - `migrations/versions/` contains one migration, `7ab42bede884_initial_schema.py`, which represents the complete schema as of this point in the project's history. Future schema changes are added as new migrations the same way (see "Changing the schema" below), not by editing that first one.

5. **Run the application:**

   ```bash
   uvicorn app.main:app --reload
   ```

   `GET /health/live` confirms the process is up; `GET /health/ready` additionally confirms the database is reachable (see "Health endpoints" below). Interactive API docs are then available at `http://127.0.0.1:8000/docs`.

### Changing the schema

After changing a model in `app/db/models.py`, generate a new migration rather than hand-writing one from scratch, then review the generated file before committing it (autogenerate is reliable for the common cases - new tables/columns/indexes - but doesn't reliably detect everything, e.g. some constraint renames):

```bash
alembic revision --autogenerate -m "describe the change"
```

`tests/test_migrations.py` fails the test suite if a model and the applied migrations ever drift apart - a model changed without a matching migration (or vice versa) is caught there, not discovered later against a real database.

### Health endpoints

Two endpoints, deliberately separate (see `app/api/routes/health.py`), so a caller can distinguish "the application process is up" from "the application's database dependency is also reachable" - two different failure modes that call for different responses:

- **`GET /health/live`** - liveness. Always `200` if the process can handle a request at all; never touches the database.
- **`GET /health/ready`** - readiness. `200` if the database is reachable (a real `SELECT 1`, not just that a connection object was constructed); `503` if not. Never leaks a raw database error - see `docs/security-logging-design.md`.

Both are unauthenticated and not rate-limited - see `docs/defensive-limits-design.md`.

## Testing

The test suite runs against a dedicated, disposable PostgreSQL database - see `docker-compose.test.yml` and `.env.test` (committed; it holds only throwaway test credentials, never real secrets). This is a separate container, volume, port, and database name from the development database in `docker-compose.yml`/`.env`, so running tests can never touch a developer's normal local database. `tests/conftest.py` enforces this at two independent levels: it always loads `.env.test`, regardless of what's already set in your shell environment, and it refuses to run at all if the configured database's name doesn't end in `_test`.

Prerequisites: Docker, and the Python dependencies installed (`pip install -r requirements.txt`, ideally in a virtual environment).

1. **Start the test dependency:**

   ```bash
   docker compose -f docker-compose.test.yml up -d
   ```

2. **Run the complete test suite:**

   ```bash
   pytest
   ```

3. **Run the suite with coverage** (line and branch coverage; fails the command if total coverage drops below 70%, per `pyproject.toml`):

   ```bash
   pytest --cov=app --cov-report=term-missing
   ```

4. **Clean up the test environment:**

   ```bash
   docker compose -f docker-compose.test.yml down -v
   ```

No other setup is required - `tests/conftest.py` applies the same Alembic migrations described in "Setup" above automatically (against the dedicated test database only) the first time the suite runs.
