# SealedArena dashboard add-on

The full local project setup, including PostgreSQL, event processing, model configuration, verification, security, and recovery steps, is documented in the project-root [`README.md`](../README.md).

The enhanced dashboard is served locally at `http://localhost:8082`. It shows readiness, filtered/paginated event history, retries, and stored analysis results. Check its health with:

```sh
curl -fsS http://localhost:8082/health
curl -fsS http://localhost:8082/api/dashboard
```
