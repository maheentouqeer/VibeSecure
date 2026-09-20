# Load test

Finds where the scan pipeline breaks under concurrent use (v4 Phase 2).

```
# terminal 1: the API with a stub scanner that takes 1.5 s per scan
DATABASE_URL=postgresql+psycopg2://... python -m loadtest.server --port 8800 --scan-ms 1500

# terminal 2: ramp up concurrent users
python -m loadtest.run --base http://127.0.0.1:8800 --levels 25,100,250,500 --poll 1.5 --json results.json
```

`loadtest.server` swaps the scanner and the AI agents for a stub. Everything else is real: the HTTP layer, the
database, the job queue, the worker threads and the connection pool. So this measures the **software's** limits, not
Semgrep, Gemini, or your host's CPU. Rate limits and the daily cap are switched off so they don't hide real limits.

Each virtual user submits one scan and polls it to completion, exactly as the frontend does (polling the light
`/scans/{id}/status` endpoint, then fetching the full scan once). Three readers hit `/healthz` throughout, so you can
see whether ordinary requests stay fast while scans pile up. Useful flags: `--full-poll` (poll the heavy endpoint, to
compare), `--poll` (seconds between polls; the frontend uses 1.5), `--timeout`, `--cooldown`.

**Never run this against production.** It creates real scan records, and against a real scanner it spends real money
(Gemini) and CPU. Use a staging copy.

## What it found, and what was fixed

Measured on a development laptop with a 1.5 s stub scan. The first table is the code before the fix.

| Concurrent users | Result before (SQLite) |
|---|---|
| 10 | all 10 succeed |
| 25 | 11 of 25 succeed, submit p95 30 s |
| 50 | 12 of 50 succeed, throughput 0.3 scans/s |

Four separate problems, found one after another (each hid the next):

1. **A running scan held a database connection for its whole run.** With a pool of 15, 15 concurrent scans starved
   every web request (`QueuePool limit ... reached`). Scans now read what they need, release the connection, run, then
   save with a fresh one.
2. **Each queued scan pinned its request's connection.** FastAPI keeps a request's session open until its background
   task finishes, so scans waiting for a turn held one connection each. The response is now serialized and the
   connection released before the request returns.
3. **Waiting scans blocked the web server's own threads.** 40 waiting scans left no thread free to answer even
   `/healthz`. Scans now run on their own small pool (`SCAN_CONCURRENCY`); waiting scans sit in its queue.
4. **Polling was expensive.** Every poll loaded the scan and all its findings. Polling now uses a tiny status endpoint.
   The connection pool default was also raised from 15 to 40 to match the 40 request threads.

After the fixes, on Postgres 17 (poll every 1.5 s):

| Concurrent users | `SCAN_CONCURRENCY=3` | `SCAN_CONCURRENCY=8` |
|---|---|---|
| 100 | 100 / 100 ok, 2.5 scans/s | 100 / 100 ok, 5.1 scans/s |
| 250 | 250 / 250 ok, 2.5 scans/s | 250 / 250 ok, 5.4 scans/s |
| 500 | 499 / 500 ok, 2.5 scans/s | not run |

At 500 simultaneous users: submit p95 7.5 s, `/healthz` p95 0.09 s, zero pool errors. The one failure was a client-side
connection reset, not a server error.

## Reading the results: capacity is set by the scanner, not the API

Throughput is almost exactly `SCAN_CONCURRENCY / seconds per scan` (3 ÷ 1.5 s = 2 scans/s; measured 2.5. 8 ÷ 1.5 s =
5.3; measured 5.1 to 5.4). A user waits about `queue length ÷ throughput`. The API itself was no longer the limit
in any test.

Illustration only, since I did not measure real scan times: if a real scan took 30 s, 3 slots would finish 0.1 scans/s,
so 100 simultaneous scans would take about 17 minutes to drain. Measure your real scan time (`python run_scan.py <repo>`),
then size the slots.

**Sizing `SCAN_CONCURRENCY`:** each real scan runs Semgrep (a CPU-heavy process, often several hundred MB of RAM), so
start near your vCPU count and watch memory. To go beyond one machine, set `SCAN_WORKER_MODE=external` and run more
`python -m backend.worker` processes (`WORKER_CONCURRENCY` each); they share the database queue.

**Database connections:** each API or worker process may open up to `DB_POOL_SIZE + DB_MAX_OVERFLOW` (default 20 + 20).
Keep the total across all processes under your database's `max_connections`.

## Limits of this test

- The scanner is a stub. Real scan duration, Semgrep memory, git clone time and Gemini rate limits are not exercised.
- It ran on one laptop, with the load generator on the same machine, so it says nothing about your hosting plan's CPU
  or network. Re-run it against staging on the real plan.
- SQLite is single-writer: at 500 users it produced two `database is locked` errors that Postgres does not. Use
  Postgres for any number you plan to quote.
