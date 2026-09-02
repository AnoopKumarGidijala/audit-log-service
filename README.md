# Audit Log Service

A tamper-evident audit log service that records application and system events in a way that allows their integrity to be independently verified after the fact.

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

No other setup is required - the database schema is created automatically on the first test run.
