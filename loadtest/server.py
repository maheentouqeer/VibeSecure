"""The API with a stub scanner, for load testing.

    python -m loadtest.server --port 8800 --scan-ms 1500 --findings 8

Replaces the scanner and the AI agents with a function that blocks for
`--scan-ms` (as a real scan does) and returns `--findings` fake findings. That
leaves everything else real: the HTTP layer, auth and rate-limit code, the
database, the job queue, worker threads and connection pool. So the test finds
where THIS software's limits are, without spending Gemini money or needing
Semgrep and network access. It is not a test of scan quality or of your
hosting plan's CPU; see loadtest/README.md.

Configure the database and limits with the usual environment variables
(DATABASE_URL, SCAN_WORKER_MODE, WORKER_CONCURRENCY, ...). Rate limits and the
daily cap are switched off unless you set them, so they don't hide real limits.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# A load test must not be throttled by the abuse controls it is not measuring.
for _name in ("SCAN_RATE_LIMIT_PER_HOUR", "DAILY_SCAN_CAP", "MUTATION_RATE_LIMIT_PER_HOUR"):
    os.environ.setdefault(_name, "0")


def make_stub(scan_ms: int, findings: int):
    def fake_scan(target, **kwargs):
        time.sleep(scan_ms / 1000)  # blocking, like the real scanners
        return {
            "target": target,
            "platform": "generic",
            "commit_sha": None,
            "unchanged": False,
            "findings": [
                {
                    "category": "hardcoded_secret",
                    "label": f"Load test finding {i}",
                    "file": f"src/module_{i}/config.ts",
                    "severity": ("critical", "high", "medium", "low")[i % 4],
                    "what_it_means": "What it means. " * 8,
                    "why_it_matters": "Why it matters. " * 8,
                    "fix_prompt": "Fix prompt text. " * 12,
                }
                for i in range(findings)
            ],
        }

    return fake_scan


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8800)
    parser.add_argument("--scan-ms", type=int, default=1500, help="how long each fake scan takes")
    parser.add_argument("--findings", type=int, default=8, help="findings each fake scan returns")
    args = parser.parse_args()

    import uvicorn

    from backend import main as backend_main

    backend_main.run_full_scan = make_stub(args.scan_ms, args.findings)
    uvicorn.run(backend_main.app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
