"""Live Bayora access-control, seal/release, network, and audit smoke checks."""

import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
BASE = "http://localhost:8083"
COMPOSE = [
    "docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.addon.yml",
    "-f", "docker-compose.bayora.yml",
]


def local_tokens():
    values = {
        "BAYORA_RED_TOKEN": "bayora-red-local-demo",
        "BAYORA_BLUE_TOKEN": "bayora-blue-local-demo",
        "BAYORA_EVALUATOR_TOKEN": "bayora-evaluator-local-demo",
    }
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            if key in values:
                values[key] = value.strip().strip("\"'")
    for key in values:
        values[key] = os.environ.get(key, values[key])
    return values


TOKENS = local_tokens()


def request(path, token=None, data=None, expected=None, timeout=6):
    body = None if data is None else json.dumps(data).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        BASE + path, data=body, headers=headers, method="GET" if data is None else "POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        status = error.code
        result = json.loads(error.read().decode("utf-8"))
    if expected is not None and status != expected:
        raise AssertionError(f"{path} returned HTTP {status}, expected {expected}: {result}")
    return status, result


def assert_unreachable(from_service, target_service):
    script = (
        "import socket,sys; "
        f"host={target_service!r}; "
        "\ntry: socket.getaddrinfo(host,8100)\n"
        "except socket.gaierror: sys.exit(0)\n"
        "sys.exit(1)"
    )
    subprocess.run(
        COMPOSE + ["exec", "-T", from_service, "python", "-c", script],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main():
    _, ready = request("/ready", expected=200)
    if not all(ready.get("dependencies", {}).values()):
        raise AssertionError(f"Bayora dependencies are not healthy: {ready}")

    assert_unreachable("bayora-red", "bayora-blue")
    assert_unreachable("bayora-red", "bayora-model")
    assert_unreachable("bayora-blue", "bayora-red")
    assert_unreachable("bayora-blue", "bayora-model")
    assert_unreachable("bayora-model", "bayora-red")
    assert_unreachable("bayora-model", "bayora-blue")

    request("/api/me", TOKENS["BAYORA_RED_TOKEN"], expected=200)
    request("/api/policies", TOKENS["BAYORA_RED_TOKEN"], expected=403)
    _, created = request("/api/runs", TOKENS["BAYORA_EVALUATOR_TOKEN"], {
        "name": "Bayora integration boundary check",
        "pack_id": "safe_prompt_boundary_v1",
        "policy_profile": "baseline",
    }, expected=201)
    run_id = created["run_id"]
    request(f"/api/runs/{run_id}/start", TOKENS["BAYORA_EVALUATOR_TOKEN"], {}, expected=202)

    deadline = time.time() + 20
    run = None
    while time.time() < deadline:
        _, run = request(f"/api/runs/{run_id}", TOKENS["BAYORA_BLUE_TOKEN"])
        if run["status"] == "sealed":
            break
        if run["status"] == "failed":
            raise AssertionError(f"Evaluation failed: {run}")
        time.sleep(0.25)
    if not run or run["status"] != "sealed":
        raise AssertionError(f"Evaluation did not seal: {run}")

    request(f"/api/runs/{run_id}/artifacts", TOKENS["BAYORA_BLUE_TOKEN"], expected=423)
    request(f"/api/runs/{run_id}/release", TOKENS["BAYORA_RED_TOKEN"], {}, expected=403)
    _, report = request(f"/api/runs/{run_id}/release", TOKENS["BAYORA_EVALUATOR_TOKEN"], {}, expected=200)
    if report["canary_exposure_count"] != 2:
        raise AssertionError(f"Synthetic baseline did not show the two expected canary findings: {report}")
    if not report.get("integrity_verified") or not report.get("run_data_integrity_verified"):
        raise AssertionError("Released report or sealed run data failed integrity verification")
    request(f"/api/runs/{run_id}/artifacts", TOKENS["BAYORA_BLUE_TOKEN"], expected=200)

    _, audit_result = request("/api/audit/verify", TOKENS["BAYORA_EVALUATOR_TOKEN"], expected=200)
    if not audit_result.get("verified"):
        raise AssertionError(f"Audit chain verification failed: {audit_result}")

    print("PASS: Red, Blue, and model workers cannot resolve each other's service names")
    print("PASS: Red cannot read Blue policies; Blue cannot read sealed run artifacts")
    print("PASS: evaluator release unlocks the report and artifacts")
    print("PASS: the baseline mock exposes only its two expected synthetic canaries")
    print("PASS: run data, report digest, and append-only audit chain verify")


if __name__ == "__main__":
    main()
