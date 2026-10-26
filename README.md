# SealedArena

SealedArena is a local Docker Compose event-processing prototype. Red submits events, Broker validates and persists them, Blue claims and analyzes them, LLM returns a validated advisory result, and the Dashboard displays service readiness, event state, and analysis.

## Start the full local stack

1. Keep the private `.env` file for this checkout. For a fresh copy, run `cp .env.example .env` and replace both database passwords with different long random local passwords. `.env` is ignored by Git.
2. From this directory, run:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.addon.yml up --build -d
   ```

3. Open `http://localhost:8082`. The original dashboard remains available at `http://localhost:8081`.
4. To send another sample event, run:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.addon.yml run --rm red
   ```

The Broker, LLM, and dashboards bind to localhost. PostgreSQL is available only on the Compose network. PostgreSQL uses a separate, non-superuser `sealed_arena` account for the application. The application containers run without root privileges, have read-only filesystems, drop Linux capabilities, and disallow privilege escalation.

## Data and event contracts

Broker assigns each event a stable database ID and stores `source`, `type`, `received_at`, the original JSON `payload`, status, attempt count, and retry timing. Status transitions are `pending` → `processing` → `completed`, or `pending` → `processing` → `failed` after bounded retries. Red sends an `Idempotency-Key`; duplicate submissions with the same key return the original event.

Blue claims work through Broker instead of polling and reprocessing the entire in-memory event list. A successful analysis is validated and stored once per event. Analysis records include severity, explanation, confidence, recommendation, provider/model, prompt version, and timestamp. Recommendations are advisory and are never executed.

The live in-memory Broker history was snapshotted to `legacy_events.json` before the storage upgrade. Startup imports those event IDs, timestamps, and payloads into PostgreSQL as completed legacy records. Their old analysis existed only in Blue's logs, so no historical analysis is fabricated. New events and analyses are stored in the named `sealedarena-postgres-data` volume.

`schema.sql` is the schema baseline. Broker applies its idempotent DDL at startup and records schema version 1 in `schema_migrations`; future schema changes should be additive, versioned, and safe to reapply.

## Dashboard

The add-on dashboard at port 8082 displays readiness for Broker, PostgreSQL, Blue, LLM, the original Dashboard, and the add-on. Its event view supports search, status/severity filters, pagination, processing attempts, errors, and the structured analysis linked to each event. It refreshes every three seconds.

Useful endpoints:

```sh
curl -fsS http://localhost:8000/ready
curl -fsS http://localhost:8000/events?limit=20
curl -fsS http://localhost:8000/stats
curl -fsS http://localhost:8082/health
curl -fsS http://localhost:8082/api/dashboard
```

`/health` reports whether a process is alive; `/ready` checks whether its dependencies are usable. The dashboard uses readiness checks.

## LLM provider

The safe default is `LLM_PROVIDER=mock`; this produces a clearly labeled mock result. To use an OpenAI-compatible local or remote endpoint, set `LLM_PROVIDER=openai_compatible`, `OPENAI_BASE_URL`, and `OPENAI_MODEL` in `.env`. Set `OPENAI_API_KEY` only if that endpoint requires it, then rebuild the LLM service.

When this mode is enabled, event payloads are sent to the configured endpoint for analysis. Choose and trust that endpoint before enabling it. Do not put credentials in source files or logs. A remote model response is treated as untrusted JSON and validated before storage.

## Verification

Run the local unit checks:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

With the full Compose stack running, exercise idempotency, processing, result storage, and dashboard visibility:

```sh
python3 tests/integration.py
```

To additionally restart Broker and check that the event and analysis remain available:

```sh
python3 tests/integration.py --restart-broker
```

To verify PostgreSQL restart recovery, or simulate an LLM response timeout and confirm retry recovery:

```sh
python3 tests/integration.py --restart-postgres
python3 tests/integration.py --exercise-timeout
```

Inspect service logs with:

```sh
docker compose -f docker-compose.yml -f docker-compose.addon.yml logs -f broker blue llm
```

## Backup and recovery

Make a database backup before upgrades or destructive maintenance:

```sh
docker compose -f docker-compose.yml -f docker-compose.addon.yml exec -T postgres pg_dump -U sealed_arena sealed_arena > sealedarena-backup.sql
```

Restore into a running database with:

```sh
cat sealedarena-backup.sql | docker compose -f docker-compose.yml -f docker-compose.addon.yml exec -T postgres psql -U sealed_arena -d sealed_arena
```

Use `docker compose ... stop` or `down` to stop the stack. **Do not use `down -v` unless you intentionally want to delete the PostgreSQL data volume.** Keep the SQL backup separate from the project directory.

## Current scope

This setup is hardened for local development, not public deployment. It has no user authentication because the host-facing services bind to localhost. Before exposing anything to other machines, add authentication and TLS, store secrets using the deployment platform's secret manager, review network boundaries, and test backup restoration.
