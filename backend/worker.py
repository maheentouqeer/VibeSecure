"""Standalone job worker:  python -m backend.worker

Use with SCAN_WORKER_MODE=external on the API so scans run outside the web
process. Start as many workers as you need (they share the database queue
safely). WORKER_CONCURRENCY sets how many jobs one worker runs at once
(default 2). SIGINT/SIGTERM finish the current jobs, then exit.
"""
import logging
import os
import signal
import threading

from backend import db, jobs
import backend.main  # noqa: F401  (importing it registers the job handlers)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db.init_db()

    concurrency = max(1, int(os.getenv("WORKER_CONCURRENCY", "2")))
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    logging.getLogger(__name__).info("worker %s started (concurrency %d)", jobs.worker_id(), concurrency)
    threads = [
        threading.Thread(target=jobs.maintenance_loop, args=(stop, True), name=f"worker-{i}")
        for i in range(concurrency)
    ]
    for t in threads:
        t.start()
    while not stop.wait(1):
        pass
    for t in threads:
        t.join()
    logging.getLogger(__name__).info("worker stopped")


if __name__ == "__main__":
    main()
