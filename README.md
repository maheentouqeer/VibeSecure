# Secure-VibeCode

Secure-VibeCode is an AI-powered security gate and vulnerability scanner designed specifically for vibe-coded applications (built with tools like Lovable, Bolt.new, v0, Cursor, Replit, or Copilot). It scans repositories or live URLs for exposed secrets, missing access controls, and common logic flaws, providing plain-English explanations and ready-to-use fix prompts for your AI coding assistant.

## Architecture Overview

The project is structured into several key layers:

1. **Scanner Layer (`scanner/`)**
   - `secrets_scanner.py`: Detects hardcoded secrets (AWS, Stripe, GitHub, etc.) using regex patterns and Shannon entropy scoring.
   - `supabase_rls_checker.py`: Flags Supabase tables created in SQL migrations without Row-Level Security (RLS) enabled.
   - `code_scanner.py`: Runs Semgrep's free security-audit and secrets rule packs.
   - `live_scanner.py`: Performs external, read-only checks against live deployed URLs (exposed `.env`, missing security headers, open CORS).
   - `platform_detector.py`: Heuristically fingerprints the target platform (Lovable, Bolt, Replit, etc.).

2. **Agent Layer (`agents/`)**
   - `triage_agent.py`: Uses Gemini to deduplicate and rank raw findings by real-world severity.
   - `explainer_agent.py`: Uses Gemini to generate plain-language explanations ("What it means" and "Why it matters").
   - `fixprompt_agent.py`: Uses Gemini to generate tailored, actionable prompts to feed back into your vibe-coding tool to fix the issue.
   - `verify_agent.py`: Deterministically diffs findings between scans to verify resolved issues.

3. **Backend Layer (`backend/`)**
   - FastAPI application (`main.py`) with SQLAlchemy persistence (`db.py`) supporting SQLite/Postgres.
   - Implements an anonymous ownership model using `X-Owner-Token` headers.

4. **Frontend Layer (`frontend/`)**
   - Next.js single-page application (`frontend/app/page.tsx`) with a beautiful, responsive dark/light UI.

5. **Evaluation Harness (`eval/`)**
   - `evaluate.py`: Runs the scanner suite against synthetic test fixtures (`test_set.py`) to measure Precision, Recall, and F1 accuracy.

---

## Getting Started

### Prerequisites

Across all operating systems, make sure you have the following installed:
- **Git**: [git-scm.com](https://git-scm.com/) (required to clone target repositories for scanning).
- **Python 3.11+**: [python.org](https://www.python.org/downloads/) (make sure to select "Add Python to PATH" on Windows).
- **Node.js 18+ & npm**: [nodejs.org](https://nodejs.org/) (required to run the Next.js frontend).
- **Semgrep (optional)**:
  - **macOS / Linux**: Install via `pip install semgrep` or Homebrew (`brew install semgrep`).
  - **Windows**: Semgrep CLI runs natively on Linux and macOS; on Windows, Semgrep is supported through WSL2 (Windows Subsystem for Linux) or Docker. If omitted, Secure-VibeCode will safely skip Semgrep checks and continue running secrets, live URL, and Supabase RLS scans.

---

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/secure-vibecode.git
cd secure-vibecode
```

---

### 2. Backend Setup

#### Step A: Create and Activate a Virtual Environment

- **macOS / Linux (Bash or Zsh):**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

- **Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  .venv\Scripts\Activate.ps1
  ```
  *(If script execution is disabled on PowerShell, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in your session first)*

- **Windows (Command Prompt / CMD):**
  ```cmd
  python -m venv .venv
  .venv\Scripts\activate.bat
  ```

#### Step B: Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

*(Optional static analysis runner: `pip install semgrep` on macOS/Linux/WSL)*

#### Step C: Configure Environment Variables

Create a `.env` file from `.env.example`:

- **macOS / Linux:**
  ```bash
  cp .env.example .env
  ```

- **Windows (PowerShell):**
  ```powershell
  Copy-Item .env.example .env
  ```

- **Windows (Command Prompt):**
  ```cmd
  copy .env.example .env
  ```

Configure your environment variables in `.env`:
```env
GEMINI_API_KEY=your_gemini_api_key_here
DATABASE_URL=sqlite:///./secure_vibecode.db
ALLOWED_ORIGINS=http://localhost:3000
```
> **Note**: An API key from [Google AI Studio](https://aistudio.google.com/) is recommended for triage, explanation, and fix prompt generation. If left unset, deterministic heuristic fallbacks will automatically be used.

#### Step D: Run the FastAPI Server

```bash
uvicorn backend.main:app --reload --port 8000
```
The API server will run on [http://localhost:8000](http://localhost:8000) (interactive OpenAPI docs at [http://localhost:8000/docs](http://localhost:8000/docs)).

---

### 3. Frontend Setup

Open a new terminal window or tab, and navigate to the frontend directory:

```bash
cd frontend
```

#### Step A: Install Node Dependencies

```bash
npm install
```
#### For Linux Users: 
```bash
npm install --save-optional --os=linux --os=darwin --os=win32 @tailwindcss/oxide
```

#### Step B: (Optional) Configure Frontend API URL

By default, the frontend connects to `http://localhost:8000`. To customize this, create a `.env.local` file inside the `frontend/` directory:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

#### Step C: Run the Next.js Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your web browser.

---

## API Behavior Notes

- **Async scans:** `POST /scans` and `POST /scans/{id}/rescan` return `202` immediately; poll `GET /scans/{id}` until `status` is `completed` or `failed` (`error` holds the reason). A rescan already in progress returns `409`.
- **Limits:** `SCAN_RATE_LIMIT_PER_HOUR` (per client IP, `429`) and `DAILY_SCAN_CAP` (global per UTC day, `503`). Set either to `0` to disable. Other endpoints are throttled too (GitHub connect, org changes and deletions, and bad webhook signatures; see `.env.example`). Hits are counted in the database (`RATE_LIMIT_STORE=db`, the default), so the limits are exact across instances and survive restarts; `RATE_LIMIT_STORE=memory` keeps them per process.
- **Target safety:** private, loopback, link-local and internal addresses are refused (SSRF guard), including IPv4 addresses hidden inside IPv6 ones. Addresses are validated on the socket that actually connects, so DNS rebinding can't redirect a fetch inward, and `git clone` is pinned to the validated addresses (needs git 2.37+). Set `ALLOW_PRIVATE_TARGETS=1` for local development only.
- **Migrations:** Alembic runs automatically at startup. After editing models in `backend/db.py`, run `alembic revision --autogenerate -m "message"` and commit the new file (see `migration_db.txt`).
- **Badge:** `GET /badge/{scan_id}.svg` is public and shows only verified / not verified.
- **Monitoring:** set `SENTRY_DSN` to enable Sentry (off by default).
- **Re-scan on push:** set `GITHUB_WEBHOOK_SECRET`, then add a GitHub repo webhook (Payload URL `https://<your-api>/webhooks/github`, content type `application/json`, "push" events, same secret). Pushes to the default branch re-scan every repo someone already scanned; unsigned requests get `401`, and the endpoint stays disabled (`503`) with no secret.
- **Unchanged commits:** a rescan of a repo still at the commit it was last scanned at skips the scanners and LLM calls. It is not skipped if the previous scan was incomplete (e.g. Semgrep failed), so a rescan works as a retry.

---

## Accounts, Plans & Teams (optional)

Everything works anonymously out of the box. To add real accounts:

- **Sign-in (Clerk):** set `CLERK_JWKS_URL` (and ideally `CLERK_ISSUER` and `CLERK_AUTHORIZED_PARTIES`). The frontend sends the Clerk session token as `Authorization: Bearer <token>`. A request with an invalid token is rejected with `401`, never treated as anonymous.
- **Claiming scans:** after sign-in, `POST /me/claim` (with the browser's `X-Owner-Token`) moves that browser's anonymous scans into the account. From then on the old token no longer grants access to them.
- **Plans:** `GET /me` returns the plan, limits, and this month's usage. Limits are only enforced when `ENFORCE_PLAN_LIMITS=1` (free: 5 scans/month, no re-scan on push, 1 org seat; pro: unlimited, re-scan on push; team: 5 seats). Over-limit requests get `402`.
- **Billing:** `POST /webhooks/billing` (needs `BILLING_WEBHOOK_SECRET`, HMAC-SHA256 in `X-Billing-Signature: sha256=<hex>`) accepts provider-neutral events: `subscription.activated|updated|canceled|expired` with `plan` (`pro` for a `user`, `team` for an `org_id`), `provider_subscription_id`, optional `status` and `current_period_end`. Connect a payment provider (Whop, Stripe, Paddle, ...) by mapping its events to this shape. A canceled subscription stays active until the period the customer paid for ends.
- **Teams:** `POST /orgs`, `GET /orgs`, `POST /orgs/{id}/members` (the person must have signed in once), `DELETE /orgs/{id}/members/{user_id}`. Pass `org_id` to `POST /scans` to file a scan under an organization. Owners and admins get `GET /orgs/{id}/dashboard`: pass/fail for every member's projects (latest scan of each) and read access to those scans.

---

## What Is Sent to the AI

Explanations and fix prompts are written by Google's Gemini. Before anything reaches it, `agents/privacy.py` masks the finding, and the answer is put back together locally, so users still read real file names.

**Sent:** the kind of issue (category and label, for example "Stripe Secret Key" or "Row-Level Security not enabled"), severity, the platform name, line numbers, and the scanner's rule text, with the masking below applied.

**Never sent:**
- your source code
- secret values, not even their first characters
- real file paths, database table names and project URLs, which appear to the model only as placeholders such as `<FILE_1.ts>`, `<TABLE_2>` and `<URL_3>`
- credentials, tokens, JWTs, email addresses and IP addresses that show up in scanner messages, which are redacted

**Failure handling:** a placeholder the model invents or mangles beyond repair makes its answer unusable. The next model is tried, then the built-in template, so a broken or leaked value never reaches the user. Repositories are cloned and scanned on your own server; only the masked findings go to Gemini. The MCP server uses the same masking.

**Limits, so nothing is over-claimed:** a file's extension stays visible so the model knows the language. Category and label reveal what kinds of issues exist. Rule text from Semgrep is masked for paths, URLs and credentials, but an ordinary identifier that a rule happens to quote (a function or variable name) is not recognisable as sensitive and is sent. If a project is sensitive enough that this matters, leave `GEMINI_API_KEY` unset: everything then uses local templates and nothing is sent.

## Checking Your Setup

`python -m backend.setup_check` inspects the environment and reports what is misconfigured (`--live` adds read-only checks of Clerk and the Whop key, `--api URL` checks a running API's health, `--sentry-test` sends a test event). It never prints secrets and exits `1` on any failure. `GO_LIVE.md` is the step-by-step checklist for connecting the real services.

## Health Checks

- `GET /healthz` is liveness: the process is up. It never touches the database.
- `GET /readyz` is readiness: the database answers, migrations are at the version this code expects, and (with `SCAN_WORKER_MODE=external`) the queue is being drained. It returns `503` with the reason otherwise, and reports queue counts only. Point your platform's health check at `/readyz` so a bad deploy never receives traffic.

## Invite Links

Adding a member by email only works if they have already signed in once. Invite links work for anyone: `POST /orgs/{id}/invites` (owner/admin; body `{"email": optional, "role": "member"|"admin"}`) returns a single-use `token` (shown once; only its hash is stored) and, if `FRONTEND_URL` is set, a ready link `FRONTEND_URL?invite=<token>`. Share it however you like. The invitee signs up, then the frontend calls `GET /invites/preview?token=` (no sign-in; shows the organization and role) and `POST /invites/accept` `{"token": ...}` (signed in). Links expire after `INVITE_TTL_DAYS` (default 7), can be revoked (`DELETE /orgs/{id}/invites/{invite}`), work exactly once even under simultaneous clicks, hold a seat while pending, and unknown/expired/used tokens all get the same answer. Only owners can create admin invites. If an invite names an email address, only that address can accept it. The address comes from the sign-in token, so add the email claim to your Clerk session token, or create link-only invites. There is no email delivery yet; the link is yours to send.

## Organization Roles

Roles are `owner`, `admin` and `member`. Only the owner can add admins, promote or demote (`PATCH /orgs/{id}/members/{user_id}` with `{"role": "admin"|"member"}`), remove admins, transfer ownership (`POST /orgs/{id}/transfer` with `{"user_id": ...}`; the previous owner becomes an admin) or delete the organization. Admins can add and remove plain members and see the organizer dashboard. The database itself guarantees an organization has exactly one owner.

## Admin API

Set `ADMIN_API_KEY` (24+ random characters) and send it as `X-Admin-Key`; without it the endpoints return `503`. Wrong keys are locked out per IP. It is deliberately blind: counts and account metadata only, never scan targets, findings or tokens.

| Endpoint | Purpose |
|---|---|
| `GET /admin/stats` | users, scans, today's usage against the daily cap, active plans, job counts |
| `GET /admin/users?email=` | find accounts (effective plan, scan and org counts) |
| `POST /admin/users/{id}/plan` `{"days": 30, "note": "..."}` | grant a complimentary Pro plan |
| `POST /admin/orgs/{id}/plan` | grant a complimentary Team plan |
| `DELETE /admin/subscriptions/{id}` | end a complimentary plan (provider subscriptions can't be touched here) |
| `GET /admin/audit` | everything done through this API |

## Continuous Integration

`.github/workflows/ci.yml` runs on every push and pull request: the backend suite on SQLite, the backend suite on a Postgres service (after applying migrations up, down to nothing, and up again), and the frontend typecheck, lint and build. Run the suite against Postgres locally with `TEST_DATABASE_URL=postgresql+psycopg2://... pytest tests`.

## Background Jobs & Workers

Scans run through a database-backed job queue (`scan_jobs`), so they survive restarts and need no Redis. A job is claimed with one atomic UPDATE, so any number of processes can share the queue safely, and a running job's worker sends a heartbeat: if the worker dies, another one re-queues the job after `JOB_STALE_SECONDS` (up to 3 attempts, then the scan is marked failed).

- **Inline (default):** the API process runs jobs itself. Nothing else to run.
- **External:** set `SCAN_WORKER_MODE=external` on the API and run `python -m backend.worker` (the `Procfile` has a `worker:` entry) on one or more machines. `WORKER_CONCURRENCY` sets jobs per worker. SIGTERM finishes current jobs, then exits.

## Deleting Data

- `DELETE /scans/{id}` (owner only, not while running) removes the scan, its findings and queued jobs.
- `DELETE /me` removes the account and all its scans. It is refused with `409` while there is an active subscription (cancel it with the payment provider first), a running scan, or an organization that still has other members. A solo-owned organization is deleted with the account.
- `DELETE /orgs/{id}` (owner only) removes the organization; members keep their scans.
- Usage counts (`scan_runs`) are kept anonymously so deleting scans can't reset a plan's monthly limit or the daily spend cap. They contain no code or findings.
- `ANON_SCAN_RETENTION_DAYS` optionally auto-deletes old finished anonymous scans.

## Private Repositories (GitHub connection)

Pro/Team users can scan their private GitHub repos through their own account. Create a GitHub OAuth App and set `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, `GITHUB_OAUTH_REDIRECT_URI` and `TOKEN_ENCRYPTION_KEY` (see `.env.example`). Flow: `GET /integrations/github/authorize` returns the GitHub URL to send the browser to, GitHub returns to `/integrations/github/callback`, `GET /integrations/github` reports the connection, and `DELETE /integrations/github` disconnects (and revokes the grant). GitHub OAuth Apps can only read private repos with the broad `repo` scope, so users should know that is what they are granting. Tokens are stored encrypted, are only ever offered to `github.com`, and are never returned by any endpoint.

> **Server-wide token is opt-in.** A token in `GITHUB_TOKEN` (or `GITHUB_PAT`) is ignored unless `ALLOW_SERVER_GITHUB_TOKEN=1`, because with it on, anyone who can submit a URL can scan whatever that token can read. If you enable it, also set `SERVER_GITHUB_TOKEN_OWNERS=your-username,your-org` so it is only ever used for your own repositories. Users' own connections (above) are never affected by this setting.

## Checkout

`POST /billing/checkout` (signed in) with `{"plan": "pro"}` or `{"plan": "team", "org_id": "..."}` creates a Whop checkout and returns its `url` for the frontend to send the browser to. It needs `WHOP_API_KEY` and `plan_` ids in `WHOP_PLAN_MAP`. The user id (and organization id for Team) is attached to the checkout server-side, from the verified session, so a client cannot attribute a purchase to someone else; Whop copies it onto the membership and the webhook below uses it to grant the plan. Team can only be bought by the organization's owner, and existing subscribers get a `409`.

## Whop Billing

`POST /webhooks/whop` verifies Whop's Standard Webhooks signature (secret in `WHOP_WEBHOOK_SECRET`) and maps membership events to plans via `WHOP_PLAN_MAP`. Create the Whop checkout with metadata `{"clerk_user_id": "<Clerk id>"}` for Pro, or `{"clerk_user_id": "...", "org_id": "<org id>"}` for Team, so the purchase is tied to the right account. Purchases made before the customer first signs in are kept and completed at first sign-in, and out-of-order retries can't undo newer events. Test it with a Whop test webhook before going live.

---

## MCP Server (scan from inside your AI coding tool)

`mcp_server.py` exposes the scanner to Claude Code, Cursor, VS Code Copilot agent mode, Claude Desktop, and any other MCP client. It runs on your machine over stdio, and `scan_workspace` reads your project straight from disk: nothing is cloned and no GitHub token is needed.

| Tool | What it does |
|---|---|
| `scan_workspace(path)` | Scan a local folder; returns findings with explanations, fix prompts, and a stable `fingerprint` each |
| `verify_fixes(path, fingerprints)` | Re-scan and report which findings are `resolved`, `still_present`, or new |
| `scan_url(target)` | Scan a public repo URL or live app URL (private/internal addresses refused) |

Client configuration (VS Code `.vscode/mcp.json`, Cursor, Claude Desktop):

```json
{ "command": "python", "args": ["/absolute/path/to/secure-vibecode/mcp_server.py"] }
```

For Claude Code: `claude mcp add secure-vibecode -- python /absolute/path/to/secure-vibecode/mcp_server.py`. Use the Python from the virtual environment where you ran `pip install -r requirements.txt`. Set `GEMINI_API_KEY` in the environment for AI-written explanations; otherwise deterministic templates are used.

---

## Running Evaluations

To measure the precision, recall, and F1 score of the scanner suite against the curated ground-truth test benchmark dataset:

- **macOS / Linux:**
  ```bash
  python3 -m eval.evaluate
  ```

- **Windows:**
  ```bash
  python -m eval.evaluate
  ```

---

## Running Tests

To run the deterministic agent and API test suites:

- **macOS / Linux / Windows:**
  ```bash
  pytest
  ```
