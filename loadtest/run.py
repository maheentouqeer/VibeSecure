"""Load generator: ramps up concurrent scans and reports where things break.

    python -m loadtest.run --base http://127.0.0.1:8800 --levels 1,5,10,25,50,100

Each level starts that many virtual users at once. Every user submits one scan
(POST /scans), then polls it until it finishes, as the frontend does. Alongside,
a few readers keep hitting cheap endpoints so you can see whether normal
traffic stays fast while scans pile up.

Reported per level:
  * how many scans succeeded / failed, and the error codes
  * submit latency (how long POST /scans takes to answer 202)
  * end-to-end time (submit until the scan is finished)
  * reader latency under that load
  * peak queue depth, from /readyz
  * throughput (scans finished per second)

Never point this at production: it creates real scan records and, against a real
scanner, spends real money. See loadtest/README.md.
"""
import argparse
import asyncio
import json
import statistics
import sys
import time
from collections import Counter

import httpx


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))]


class Level:
    def __init__(self, users: int):
        self.users = users
        self.submit: list[float] = []
        self.e2e: list[float] = []
        self.reader: list[float] = []
        self.codes: Counter = Counter()
        self.ok = 0
        self.failed = 0
        self.timeouts = 0
        self.peak_pending = 0
        self.peak_running = 0
        self.wall = 0.0


async def one_user(client: httpx.AsyncClient, level: Level, target: str, poll: float, timeout: float, full_poll: bool = False) -> None:
    started = time.perf_counter()
    try:
        t0 = time.perf_counter()
        resp = await client.post("/scans", json={"target": target})
        level.submit.append(time.perf_counter() - t0)
        level.codes[resp.status_code] += 1
        if resp.status_code != 202:
            level.failed += 1
            return
        scan_id, token = resp.json()["id"], resp.headers["X-Owner-Token"]

        while time.perf_counter() - started < timeout:
            await asyncio.sleep(poll)
            # like the frontend: poll the light status endpoint (or the full scan with --full-poll)
            got = await client.get(f"/scans/{scan_id}" + ("" if full_poll else "/status"), headers={"X-Owner-Token": token})
            level.codes[got.status_code] += 1
            if got.status_code != 200:
                level.failed += 1
                return
            status = got.json()["status"]
            if status == "completed":
                level.ok += 1
                level.e2e.append(time.perf_counter() - started)
                return
            if status == "failed":
                level.failed += 1
                return
        level.timeouts += 1
        level.failed += 1
    except httpx.HTTPError as exc:
        level.codes[type(exc).__name__] += 1
        level.failed += 1


async def reader(client: httpx.AsyncClient, level: Level, stop: asyncio.Event) -> None:
    while not stop.is_set():
        t0 = time.perf_counter()
        try:
            resp = await client.get("/healthz")
            level.reader.append(time.perf_counter() - t0)
            if resp.status_code != 200:
                level.codes[f"healthz-{resp.status_code}"] += 1
        except httpx.HTTPError as exc:
            level.codes[f"healthz-{type(exc).__name__}"] += 1
        await asyncio.sleep(0.1)


async def sampler(client: httpx.AsyncClient, level: Level, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            body = (await client.get("/readyz")).json()
            queue = body.get("queue", {})
            level.peak_pending = max(level.peak_pending, queue.get("pending", 0))
            level.peak_running = max(level.peak_running, queue.get("running", 0))
        except (httpx.HTTPError, ValueError):
            pass
        await asyncio.sleep(0.5)


async def run_level(base: str, users: int, target: str, poll: float, timeout: float, readers: int, full_poll: bool = False) -> Level:
    level = Level(users)
    limits = httpx.Limits(max_connections=users + readers + 10, max_keepalive_connections=users + readers + 10)
    async with httpx.AsyncClient(base_url=base, timeout=60, limits=limits) as client:
        stop = asyncio.Event()
        background = [asyncio.create_task(reader(client, level, stop)) for _ in range(readers)]
        background.append(asyncio.create_task(sampler(client, level, stop)))
        t0 = time.perf_counter()
        await asyncio.gather(*(one_user(client, level, target, poll, timeout, full_poll) for _ in range(users)))
        level.wall = time.perf_counter() - t0
        stop.set()
        await asyncio.gather(*background)
    return level


def fmt(v: float) -> str:
    return "  n/a" if v != v else f"{v:5.2f}"


def report(levels: list[Level]) -> None:
    print(f"\n{'users':>5} {'ok':>4} {'fail':>4} | {'submit p50':>10} {'p95':>6} {'p99':>6} | "
          f"{'e2e p50':>7} {'p95':>6} {'max':>6} | {'read p95':>8} | {'peak queue':>10} | {'scans/s':>7}")
    for lv in levels:
        print(
            f"{lv.users:>5} {lv.ok:>4} {lv.failed:>4} | {fmt(pct(lv.submit, 50)):>10} {fmt(pct(lv.submit, 95)):>6} "
            f"{fmt(pct(lv.submit, 99)):>6} | {fmt(pct(lv.e2e, 50)):>7} {fmt(pct(lv.e2e, 95)):>6} "
            f"{fmt(max(lv.e2e) if lv.e2e else float('nan')):>6} | {fmt(pct(lv.reader, 95)):>8} | "
            f"{lv.peak_pending:>4}p/{lv.peak_running:>3}r | {lv.ok / lv.wall if lv.wall else 0:>7.2f}"
        )
    for lv in levels:
        bad = {k: v for k, v in lv.codes.items() if str(k) not in ("200", "202")}
        if bad or lv.timeouts:
            print(f"  {lv.users} users: non-OK responses {dict(bad)}" + (f", {lv.timeouts} timed out" if lv.timeouts else ""))


async def main_async(args) -> list[Level]:
    levels = []
    for users in [int(x) for x in args.levels.split(",")]:
        print(f"running {users} concurrent users ...", flush=True)
        levels.append(await run_level(args.base, users, args.target, args.poll, args.timeout, args.readers, args.full_poll))
        await asyncio.sleep(args.cooldown)
    return levels


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8800")
    parser.add_argument("--levels", default="1,5,10,25,50,100")
    parser.add_argument("--target", default="https://github.com/octocat/Hello-World")
    parser.add_argument("--poll", type=float, default=0.5, help="seconds between status polls")
    parser.add_argument("--timeout", type=float, default=180, help="give up on a scan after this long")
    parser.add_argument("--readers", type=int, default=3, help="background users hitting a cheap endpoint")
    parser.add_argument("--cooldown", type=float, default=3, help="pause between levels")
    parser.add_argument("--full-poll", action="store_true", help="poll the full scan instead of the light status endpoint")
    parser.add_argument("--json", help="also write raw results to this file")
    args = parser.parse_args()

    levels = asyncio.run(main_async(args))
    report(levels)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(
                [
                    {
                        "users": lv.users, "ok": lv.ok, "failed": lv.failed, "codes": {str(k): v for k, v in lv.codes.items()},
                        "submit_p50": pct(lv.submit, 50), "submit_p95": pct(lv.submit, 95), "submit_p99": pct(lv.submit, 99),
                        "e2e_p50": pct(lv.e2e, 50), "e2e_p95": pct(lv.e2e, 95), "reader_p95": pct(lv.reader, 95),
                        "peak_pending": lv.peak_pending, "peak_running": lv.peak_running,
                        "throughput": lv.ok / lv.wall if lv.wall else 0,
                    }
                    for lv in levels
                ],
                f, indent=2,
            )
    sys.exit(1 if any(lv.failed for lv in levels) else 0)


if __name__ == "__main__":
    main()
