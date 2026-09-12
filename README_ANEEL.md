# Secure-VibeCode — Aneel's Part (Backend & Persistence Layer)

FastAPI service that wraps Maheen's orchestrator and Ali's Verify Agent,
persists scans/findings to Postgres, and exposes the scan/rescan/badge
endpoints the frontend calls.

## File tree

```
secure-vibecode/
  backend/
    __init__.py
    main.py          # FastAPI app + route handlers
    db.py            # SQLAlchemy engine, session, models, init_db()
    schemas.py       # Pydantic request/response models
  orchestrator.py     # Maheen's real scan pipeline (run_full_scan)
  agents/
    verify_agent.py   # Ali's diff_findings(), used by the rescan endpoint
  tests/
    test_api.py
  requests.http       # curl/REST Client cheat-sheet
  requirements.txt
  .env.example
  README_ANEEL.md
```

## Setup

```bash
python -m venv venv
source venv/bin/activate          # venv\Scripts\activate on plain Windows
pip install -r requirements.txt
cp .env.example .env              # then fill in DATABASE_URL (see below)
```

Without a `.env`/`DATABASE_URL`, the app falls back to a local SQLite file
(`secure_vibecode.db`) — fine for quick local testing, but use Postgres for
the actual demo/submission.

## Hosted Postgres setup (Neon, free tier)

1. Go to https://neon.tech and sign up / log in.
2. Click **New Project**, give it a name (e.g. `secure-vibecode`), pick a
   region, and create it.
3. On the project dashboard, open **Connection Details** and copy the
   connection string — it looks like:
   ```
   postgresql://USER:PASSWORD@ep-xxxx.region.aws.neon.tech/dbname?sslmode=require
   ```
4. In your `.env`, set:
   ```
   DATABASE_URL=postgresql+psycopg2://USER:PASSWORD@ep-xxxx.region.aws.neon.tech/dbname?sslmode=require
   ```
   (Note the `+psycopg2` — SQLAlchemy needs the driver named explicitly.)
5. That's it — no manual `CREATE TABLE` needed. `init_db()` runs on app
   startup and creates `scans`/`findings` automatically via
   `Base.metadata.create_all`.

(Supabase or Railway work the same way — create a project, copy the
Postgres connection string from their dashboard, paste it into
`DATABASE_URL` with the `+psycopg2` driver prefix.)

## Deploying to Railway

1. Push this repo to GitHub (Railway deploys from a connected repo).
2. In Railway, **New Project → Deploy from GitHub repo**, and pick this repo.
   Leave the **root directory as the repo root** (not `/backend`) — `backend/main.py`
   imports `orchestrator.py`, `scanner/`, and `agents/`, which live at the repo
   root as siblings of `backend/`, so Railway needs the whole repo in the build
   context, not just the `backend/` folder.
3. Add the **PostgreSQL** plugin from Railway's marketplace — it provisions a
   database and injects `DATABASE_URL` into the service automatically, so
   nothing needs to be set by hand.
4. Set environment variables on the service:
   - `ALLOWED_ORIGINS` — the deployed frontend's origin (comma-separated if
     more than one), e.g. `https://secure-vibecode.vercel.app`. Defaults to
     `http://localhost:3000` if unset, so a deployed frontend would otherwise
     be blocked by CORS.
   - `GEMINI_API_KEY` — only needed once the agents stop being stubs.
5. Railway auto-detects the `Procfile` (`web: uvicorn backend.main:app --host
   0.0.0.0 --port $PORT`) as the start command — no need to set one manually.
6. Deploy. Railway builds from `requirements.txt` (now merged with the
   scanner/agent dependencies — `gitpython`, `requests`, `semgrep` — so the
   real orchestrator's imports resolve) and gives you a public URL.

## Run it

```bash
uvicorn backend.main:app --reload --port 8000
```

Interactive docs at http://localhost:8000/docs once it's running.

## Endpoints

| Method | Path                     | Description                                      |
|--------|--------------------------|---------------------------------------------------|
| POST   | `/scans`                 | Run a scan, persist scan + findings, return it    |
| GET    | `/scans/{id}`            | Fetch a saved scan with its findings              |
| POST   | `/scans/{id}/rescan`     | Re-run the scan, resolve findings no longer present |
| GET    | `/scans/{id}/badge`      | Badge pass/fail (fails if any open critical/high)  |

### Example curl commands

```bash
# Create a scan -- the owner token comes back on the X-Owner-Token
# response header (-i shows response headers so you can copy it)
curl -i -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://github.com/example/lovable-app"}'

# Every later request for that scan must send the token back
# (replace SCAN_ID and TOKEN with the values from the response above)
curl http://localhost:8000/scans/SCAN_ID -H "X-Owner-Token: TOKEN"
curl -X POST http://localhost:8000/scans/SCAN_ID/rescan -H "X-Owner-Token: TOKEN"
curl http://localhost:8000/scans/SCAN_ID/badge -H "X-Owner-Token: TOKEN"
```

See `requests.http` for a ready-to-run version of the same requests
(works with the VS Code "REST Client" extension).

## Ownership (no accounts, just a session token)

There's no login system. Instead:

- `POST /scans` mints an opaque token (`uuid4`) and returns it via the
  **`X-Owner-Token` response header** — never in the JSON body, so it's
  never accidentally re-exposed to a viewer who only sees a shared scan.
  If the caller already sends an `X-Owner-Token` request header (e.g. a
  second scan from the same browser session), that value is reused
  instead of minting a new one.
- `GET /scans/{id}`, `POST /scans/{id}/rescan`, and `GET /scans/{id}/badge`
  all require a matching `X-Owner-Token` request header. A missing or
  wrong token returns the same 404 as a scan that doesn't exist at all —
  deliberately not a 403 — so a caller without the token can't even
  confirm a given scan id is real.

This is intentionally *ownership*, not role-based access control: there's
no concept of admin/member/viewer tiers, teams, or shared scans, because
that's a problem this product doesn't have yet. If a cohort/organizer
dashboard managing other people's scans becomes a real need, that's a V2
item — the token model above doesn't need to be thrown away for it, just
extended.

## Running tests

```bash
python -m pytest tests/test_api.py -v
```

Tests use a throwaway SQLite file (`test_secure_vibecode.db`, auto-created
and dropped per test) and monkeypatch the orchestrator calls to be
deterministic, so they never touch `DATABASE_URL` or the real stub's
randomness. Covers: create scan, get by id, all three rescan scenarios,
badge pass/fail, ownership enforcement (missing/wrong token), invalid
target URLs, and the 404/422 error paths. 18 tests total.

## How rescan works

The backend doesn't call an orchestrator-level `rescan()` — instead
`rescan_scan` in `backend/main.py` calls `run_full_scan(target)` again for
a fresh result, then hands the scan's previously-open findings and the
fresh findings to Ali's `diff_findings()` (in `agents/verify_agent.py`) to
work out which are `still_present` vs. `resolved`. Findings in the fresh
scan that weren't tracked before (matched by category/label/file) are
inserted as new, open findings — so a rescan both resolves fixed issues
and picks up newly introduced ones.

## Known limitations (V2 candidates)

- **Synchronous scan execution** — `POST /scans` and the rescan endpoint
  run the full scan inline in the request handler. Fine at hackathon
  scale (a scan takes seconds), but if scans get slow (large repos, a
  slow Gemini call), this blocks the request instead of returning
  immediately with a job id. A background queue (RQ/Celery + polling or
  webhooks) is the fix, not needed now.
- **Ownership tokens, not accounts** — see the "Ownership" section above.
  No password reset, no multi-device access to the same scan, no
  organizer/admin view across everyone's scans. Deliberate V1 scope.
