# SealedArena

SealedArena is a local security-operations practice arena. It generates safe synthetic security telemetry, detects a few explainable patterns, groups related events into analyst cases, and records a human review. It is a training prototype, not a production security monitoring service and it does not run attacks or take response actions.

## Start the local stack

Keep the private `.env` file for this checkout. For a fresh copy, run `cp .env.example .env` and set two different long random local database passwords. The `.env` file is ignored by Git.

From this directory, start the complete stack:

```sh
docker compose -f docker-compose.yml -f docker-compose.addon.yml up --build -d
```

Open the operations dashboard at [http://localhost:8082](http://localhost:8082). The original basic dashboard remains at [http://localhost:8081](http://localhost:8081).

The containers run on a private Compose network. Only the local Broker, LLM, and dashboards are published to `127.0.0.1`; PostgreSQL and the Red simulator are not exposed on the host. Application containers run as non-root users with read-only filesystems, dropped Linux capabilities, and privilege escalation disabled.

## Bayora Lab add-on

Bayora Lab is a separate local proof-of-concept for adversarial AI safety evaluation. Start it with the existing stack by adding the third Compose file:

```sh
docker compose -f docker-compose.yml -f docker-compose.addon.yml -f docker-compose.bayora.yml up --build -d
```

Open [http://localhost:8083](http://localhost:8083), or use the **Bayora Lab** link on the SealedArena dashboard. The original SOC practice dashboard remains on port 8082.

The add-on uses three synthetic roles. The controller checks bearer tokens on the server for every role-gated route. Find the role tokens in the project-root `.env` file (a hidden file in macOS Finder; press Cmd+Shift+. to show it). For a fresh checkout, copy `.env.example` to `.env`. Local demo defaults are `bayora-red-local-demo`, `bayora-blue-local-demo`, and `bayora-evaluator-local-demo`. They are for a local prototype only; replace them with separate random values in `.env` before sharing a demo. The token is held in page memory and cleared when you disconnect or reload.

### Demo workflow

1. Optionally connect as **Blue** and use the policy workbench to create an immutable policy version with the three supported controls: direct-override blocking, retrieved-text handling, and per-run session isolation. Policy versions are hash-identified in the audit chain and cannot be edited or deleted. Disconnect, then connect as **evaluator** to use that version in a run.
2. Connect as **evaluator**, choose the full five-case suite, model-only suite, or Blue-artifact-only suite, then create a run with a built-in profile (`baseline` or `strict`) or a Blue-authored policy version.
3. Start it. The controller asks the isolated Red service for five safe synthetic cases: four model boundary probes plus an access attempt against a real synthetic defense-plan file inside Blue's container. Model prompts go through the gateway to a stateless mock target by default.
4. While the run is active or sealed, Red cannot read Blue policy metadata, Blue cannot retrieve prompts or responses, and all roles see only run status and progress.
5. Connect as **evaluator** and release the sealed report. Blue scores it only after the run has sealed. The completed report then exposes the synthetic transcripts, canary result, findings, and latency measurements.
6. Connect as Red and choose **Attempt Blue private-file access**. The controller evaluates the role policy and checks Blue's real file read counter to prove the artifact was not retrieved. Connect as Blue to try the sealed-report barrier.
7. As evaluator, use **Run tamper-copy check** to alter a temporary event copy and show the hash-chain verifier catches it; the stored event history remains unchanged. Use **Verify chain & witness** to compare the chain with the separate witness checkpoint, and export or inspect the audit events.
8. For a second demo run, create and start another evaluation. Before releasing it, choose **Inject simulated critical failure**. The released report should mark environment integrity **COMPROMISED**, separate from the model-safety result. Leave this action out of the normal run to show a valid evaluation.

The selectable suites cover a benign request, direct instruction override, synthetic retrieved-text injection, cross-run memory probe, and protected Blue artifact probe. The `baseline` mock intentionally returns the synthetic canary for two adversarial cases; `strict` refuses those cases. The target model stores no conversation history and has no database or mounted volume. These are deterministic demonstration fixtures, not a calibrated real-world safety benchmark.

The Security posture panel shows blocked artifact attempts, tamper detection, critical-failure invalidation, false denials, policy-check overhead, and repeat-run consistency. Consistency stays unavailable until there are comparable repeated runs. One run is one measurement trial; the UI does not imply statistical confidence from a single trial.

### Optional controlled model endpoint

Mock mode remains the default. To evaluate an approved OpenAI-compatible local or hosted endpoint, set `BAYORA_MODEL_PROVIDER=openai_compatible`, `BAYORA_UPSTREAM_BASE_URL`, and `BAYORA_UPSTREAM_MODEL` in `.env`; set `BAYORA_UPSTREAM_API_KEY` only when required. The model service then uses the configured endpoint for each synthetic model prompt. The external endpoint receives the synthetic prompt and canary harness context, so use only a trusted endpoint and synthetic data. For outbound connectivity, include the model egress overlay when starting the stack:

```sh
docker compose -f docker-compose.yml -f docker-compose.addon.yml -f docker-compose.bayora.yml -f docker-compose.bayora.model-egress.yml up --build -d
```

The ordinary three-file command keeps the model worker on its internal-only network. The model provider and model name appear in readiness and report metadata; prompts and responses are kept out of the model container logs.

### Prototype boundaries

`docker-compose.bayora.yml` gives Red, Blue, the target model, and the witness separate internal networks; only the controller joins worker networks. The witness has its own SQLite volume and exposes a read-only checkpoint on `http://localhost:8084/checkpoint`. It is a separate service and data store, but remains on the same local Docker host. The controller stores run transcripts in its own SQLite volume; use synthetic prompts only. Demo role tokens are application-level access checks, not a real identity provider.

This demonstrates network reachability boundaries, API role checks, pre-release sealing, per-run mock session isolation, resource caps, file-level access policy enforcement, witnessed audit checkpoints, and evaluation invalidation. The controller is trusted and can see all run data. Anyone with Docker-host or repository access can inspect the prototype, its database volumes, and its source. Containers on one Docker host still rely on the host kernel, so this does not provide strong multi-tenant isolation or protection from host administrators, kernel vulnerabilities, timing side channels, or shared-model KV-cache leakage. Docker describes Compose's default network as shared service reachability and documents the kernel and daemon trust assumptions in its [networking](https://docs.docker.com/compose/how-tos/networking/) and [engine security](https://docs.docker.com/engine/security/) guidance.

The audit ledger uses a SHA-256 hash chain and append-only database triggers. A separate witness service stores the last accepted sequence and root, so rewriting the controller's ordinary audit database without also changing the witness is detectable. Both services still run on this same Docker host; this is not an external trust anchor against a host administrator.

## Render deployment

### Free preview

The root `render.yaml` is a zero-cost preview blueprint with one free web service and one free Render Postgres database. One container runs the synthetic SOC and Bayora services together; open Bayora at `/` and the SOC dashboard at `/soc`. The target model stays in mock mode, so this setup needs no OpenAI key and makes no model API calls.

Connect the GitHub repository to Render as a Blueprint and use `render.yaml`. Enter a strong SOC dashboard username and password when prompted. Render generates the three Bayora role tokens; after deploy, retrieve `BAYORA_RED_TOKEN`, `BAYORA_BLUE_TOKEN`, and `BAYORA_EVALUATOR_TOKEN` from the service's Environment page and paste the matching token into the Bayora role connection. Do not upload or commit `.env`.

This is a temporary demo setup. A free web service spins down after 15 minutes without traffic and its local files can be lost when it restarts. The Bayora controller and witness keep their SQLite state on that temporary filesystem, so Bayora run history and witness checkpoints can reset. Free Render Postgres expires after 30 days. The single-container version also does not provide separate worker network isolation. See Render's [free-instance limitations](https://render.com/docs/free) and [private-network behavior](https://render.com/docs/private-network).

### Full paid topology

`render-paid.yaml` defines the full 11-service setup, Render Postgres, and persistent disks for the Bayora controller and witness. It is not free: using Render's current smallest paid service plan at $7/month per service, Postgres starting at $6/month, and two 1 GB disks at $0.25/GB/month, the continuous estimate is about **$83.50/month**, before model API usage or any bandwidth beyond the included amount. Check [current Render pricing](https://render.com/pricing) before creating these resources.

The full topology keeps separate application services, but Render services in the same workspace and region share a private network. It demonstrates application-level roles and checks, but it **does not demonstrate the separate Docker network isolation** provided by the local Compose setup. Treat either hosted option as a synthetic-data prototype, not as production security infrastructure.

### Bayora API and checks

The UI and API are served from port 8083. Useful routes include `GET /api/security/overview`, `POST /api/security/access-attempt` (Red role only), `/api/runs/{run_id}/inject-failure` (evaluator only), `/api/audit/tamper-demo`, `/api/audit/events`, `/api/audit/verify`, and `/api/audit/export`, alongside policy and evaluation-run routes. Access requires the matching local role token. The Red, Blue, model, and witness worker APIs are private to their Compose networks; only the read-only witness checkpoint is also published on local port 8084.

Run the local checks:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tests/bayora_integration.py
```

The live integration check requires the three-file Bayora Compose stack to be running. It checks role-denied routes, the sealed-release barrier, mock canary metrics, audit verification, and that worker containers cannot resolve each other's network names. The optional model-egress overlay is needed only when using a remote target endpoint.

## Run a synthetic scenario

Choose a scenario in the dashboard and click **Run scenario**. The scenarios are deterministic in their event patterns and use documentation-only IP ranges and demo identities:

- `normal_login` — routine sign-in, with no expected case.
- `brute_force_login` — five failed sign-ins for one demo account and source address.
- `unusual_location` — successful sign-in marked as a new location.
- `suspicious_process` — unsigned synthetic process launched by a document application.

To start one from Terminal instead:

```sh
python3 red/client.py brute_force_login
```

The dashboard refreshes every three seconds. A detected pattern creates a case and links the supporting event IDs. Analysts can change its status, assign an owner, record a verdict, and add notes. These actions create a case activity history. **Clear synthetic data** deletes only scenario-generated events, cases, and run history; the UI asks for confirmation first. Other events, including imported legacy events, are preserved.

## Detection and analysis

Blue applies deterministic rules to structured fields and related events. The current rules flag five or more matching failed sign-ins within ten minutes, a successful sign-in marked as a new location, and an unsigned process launched by a document application. Each finding includes a rule ID, summary, severity, time window, and supporting event references. Rule processing continues if the optional LLM service is unavailable; in that state the dashboard shows that no LLM advice was added.

Rule findings determine the displayed system severity. The LLM can add a separate unverified summary and recommendation; it cannot create a detection or trigger a response. When no deterministic rule matches, the system severity remains `unknown`. Mock mode is clearly labeled and is not evidence of model quality.

Mock mode is the safe default. To use an OpenAI-compatible endpoint, set `LLM_PROVIDER=openai_compatible`, `OPENAI_BASE_URL`, and `OPENAI_MODEL` in `.env`; set `OPENAI_API_KEY` only if the endpoint requires it, then rebuild the LLM service. Event fields commonly containing credentials, contact details, account identifiers, IP addresses, or device identifiers are redacted before an external request. This key-based redaction is a safety aid, not a guarantee that arbitrary free text contains no sensitive data. Use synthetic or approved data and trust the configured endpoint before enabling it.

## Event and storage model

Events use a JSON object with `source`, `type`, and optional `schema_version`, `scenario_key`, `scenario_run_id`, `event_type`, `occurred_at`, identity/device fields, and message. The Broker validates required and bounded fields, assigns a stable database ID, and uses `Idempotency-Key` to avoid duplicate submissions.

Event processing states are `pending`, `processing`, `completed`, and `failed`. Blue claims eligible work with a processing lease. Failures receive bounded exponential retries, up to five attempts; a failed event can be retried from the dashboard. Scenario events stay unclaimable until the simulator marks the entire run complete, so correlation rules see the whole generated sequence.

PostgreSQL stores scenario runs, events, analyses, cases, linked evidence, and case activity. Broker applies idempotent schema statements and records schema versions in `schema_migrations`. Historical records from `legacy_events.json` are imported as completed events; no historical analysis is fabricated.

## Useful endpoints

```sh
curl -fsS http://localhost:8000/ready
curl -fsS 'http://localhost:8000/events?limit=20'
curl -fsS http://localhost:8000/cases
curl -fsS http://localhost:8000/scenario-runs
curl -fsS http://localhost:8082/health
curl -fsS http://localhost:8082/api/dashboard
```

`/health` reports whether a process is alive. `/ready` also checks dependencies. The dashboard uses readiness checks and includes the Red simulator in its service health view.

## Verification

Run unit tests for event contracts, scenario generation, deterministic rules, redaction, and case workflow validation:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

With the full Compose stack running, check event idempotency, scenario processing, evidence-linked case creation, dashboard visibility, and case updates:

```sh
python3 tests/integration.py
```

Optional recovery checks:

```sh
python3 tests/integration.py --restart-broker
python3 tests/integration.py --restart-postgres
python3 tests/integration.py --exercise-timeout
```

The timeout check pauses the LLM briefly and confirms deterministic processing still finishes with a clearly marked rules-only result.

Inspect logs with:

```sh
docker compose -f docker-compose.yml -f docker-compose.addon.yml logs -f broker red blue llm
```

## Backup and recovery

Back up the database before upgrades or maintenance:

```sh
docker compose -f docker-compose.yml -f docker-compose.addon.yml exec -T postgres pg_dump -U sealed_arena sealed_arena > sealedarena-backup.sql
```

Restore into a running database with:

```sh
cat sealedarena-backup.sql | docker compose -f docker-compose.yml -f docker-compose.addon.yml exec -T postgres psql -U sealed_arena -d sealed_arena
```

Stop the stack with `docker compose -f docker-compose.yml -f docker-compose.addon.yml down`. Do not use `down -v` unless you intend to delete the PostgreSQL data volume. Keep SQL backups outside the project directory.

## Scope and next steps

This version is for local demos and training with synthetic events. It has no user authentication, role management, external event connectors, calibrated model evaluation, production retention policy, or public deployment support. The audit actor is `local-analyst` until real authentication is added. Before exposing it to other machines, add authentication and authorization, TLS, managed secret storage, a retention policy, a threat model, and tested backup restoration. Any response automation should require an authenticated human approval and an audit record.
