"""Command-line helper to start a local SealedArena demo scenario."""

import argparse
import json
import os
from urllib.request import Request, urlopen


SCENARIOS = ("normal_login", "brute_force_login", "unusual_location", "suspicious_process")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS, help="synthetic scenario to generate")
    parser.add_argument(
        "--dashboard-url",
        default=os.environ.get("SEALED_ARENA_DASHBOARD_URL", "http://localhost:8082"),
        help="local dashboard base URL",
    )
    args = parser.parse_args()
    request = Request(
        args.dashboard_url.rstrip("/") + "/api/scenarios/run",
        data=json.dumps({"scenario_id": args.scenario}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=15) as response:
        result = json.loads(response.read().decode("utf-8"))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
