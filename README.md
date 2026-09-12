# Secure-VibeCode

Secure-VibeCode is an automated security scanner and AI-powered remediation pipeline designed specifically for applications built with vibe-coding platforms (Lovable, Supabase, Bolt.new, v0, Replit, and standard modern web stacks).

It combines multi-engine security scanning (Semgrep static analysis, regex & Shannon entropy secret scanning, Supabase Row-Level Security verification, and black-box live app probing) with Google Gemini AI agents to translate technical vulnerabilities into plain-English explanations and copy-paste prompts tailored for AI coding assistants.

---

## Quick Terminal Setup (TL;DR)

Get up and running locally in two minutes with two terminal tabs:

### 1. Terminal 1 — Backend & Core Engine

```bash
# Clone the repository
git clone <repo-url>
cd secure-vibecode

# Create and activate virtual environment
python -m venv venv
# Linux / macOS / WSL:
source venv/bin/activate
# Windows (PowerShell):
# .\venv\Scripts\Activate.ps1
# Windows (CMD):
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Setup environment variables
cp .env.example .env

# Run FastAPI backend (defaults to local SQLite if DATABASE_URL is not set)
uvicorn backend.main:app --reload --port 8000
```
- API Docs will be live at: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### 2. Terminal 2 — Next.js Frontend

```bash
cd secure-vibecode/frontend

# Install dependencies
npm install

# Start Next.js dev server
npm run dev
```
- Web Application will be live at: [http://localhost:3000](http://localhost:3000)

---

### 3. Quick CLI Scan (No server needed)

You can run scans directly from your terminal using Python alone:

```bash
# Linux / macOS / WSL:
source venv/bin/activate
python run_scan.py https://github.com/example/public-repo
# Or against a live URL:
python run_scan.py https://example.vercel.app
```

---

## Table of Contents

1. [Quick Terminal Setup (TL;DR)](#quick-terminal-setup-tldr)
2. [Architecture & System Flow](#architecture--system-flow)
3. [Component Overview](#component-overview)
   - [Core Scanning Engine & Orchestrator](#core-scanning-engine--orchestrator)
   - [AI Agent Layer](#ai-agent-layer)
   - [Backend & Persistence Layer](#backend--persistence-layer)
   - [Frontend Web Application](#frontend-web-application)
   - [Detection Quality & Evaluation Suite](#detection-quality--evaluation-suite)
4. [Environment Configuration](#environment-configuration)
5. [Installation & Local Setup](#installation--local-setup)
   - [Backend & CLI Setup](#backend--cli-setup)
   - [Frontend Setup](#frontend-setup)
6. [Running Scans via CLI](#running-scans-via-cli)
7. [Running Scanner Evaluation Harness](#running-scanner-evaluation-harness)
8. [API Reference & Ownership Model](#api-reference--ownership-model)
9. [Testing](#testing)
10. [Deployment Guide](#deployment-guide)
    - [Deploying Backend to Railway](#deploying-backend-to-railway)
    - [Deploying Frontend to Vercel](#deploying-frontend-to-vercel)
11. [Design Decisions & Roadmap](#design-decisions--roadmap)

---

## Architecture & System Flow

```
                          +-------------------------+
                          |    Next.js Frontend     |
                          |  (Tailwind, TypeScript) |
                          +------------+------------+
                                       |
                     REST API + JSON   | Header: X-Owner-Token
                                       v
                          +-------------------------+
                          |     FastAPI Backend     |
                          |   (backend/main.py)     |
                          +------+------------+-----+
                                 |            |
                 SQLAlchemy ORM  |            | Invokes pipeline
                                 v            v
                   +---------------+    +------------------------+
                   | PostgreSQL /  |    |      Orchestrator      |
                   | SQLite DB     |    |   (orchestrator.py)    |
                   +---------------+    +-----------+------------+
                                                    |
            +---------------------------------------+---------------------------------------+
            |                                                                               |
            v                                                                               v
+-------------------------------+                                           +-------------------------------+
|     Core Scanning Engine      |                                           |        AI Agent Layer         |
|          (scanner/)           |                                           |           (agents/)           |
+-------------------------------+                                           +-------------------------------+
| • repo_utils: shallow git clone| -- [Raw Findings] ----------------------> | • Triage Agent (Gemini Flash) |
| • platform_detector: stack ID |                                           |   Deduplicates & re-ranks sev |
| • secrets_scanner: entropy+regex                                         | • Explainer Agent (Gemini)    |
| • code_scanner: Semgrep packs |                                           |   What it means & why matters |
| • supabase_rls: migration RLS |                                           | • Fix-Prompt Agent (Gemini)   |
| • live_scanner: headers, CORS | <--- [Verification Diff on Rescan] ------ |   Tailored prompts for AI IDEs|
+-------------------------------+                                           +-------------------------------+
```

---

## Component Overview

### Core Scanning Engine & Orchestrator

The scanner subsystem analyzes either a source code git repository or a live deployed web application without requiring external services:

- **`scanner/repo_utils.py`**: Handles shallow cloning (`depth=1`) of public git repositories into safe temporary directories (`svc_scan_*`) and manages post-scan cleanup.
- **`scanner/platform_detector.py`**: Identifies project stacks and vibe-coding platforms (`lovable_supabase`, `bolt_v0`, `replit`, or `generic`) through file presence (`package.json`, `.replit`, etc.) and dependency fingerprinting.
- **`scanner/secrets_scanner.py`**: Multi-layered secret scanner combining pattern matching for known cloud tokens (AWS, Stripe, Google, GitHub) with **Shannon entropy scoring** ($H(X) \ge 4.5$) to detect unstructured high-entropy secrets and keys that regex alone misses.
- **`scanner/code_scanner.py`**: Executes Semgrep rulesets (`p/security-audit`, `p/secrets`) to uncover code vulnerabilities, injection risks, and deserialization flaws.
- **`scanner/supabase_rls_checker.py`**: Scans SQL schema files and migrations to locate `CREATE TABLE` definitions that lack an associated `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` statement.
- **`scanner/live_scanner.py`**: Performs zero-source black-box HTTP probing against target URLs to check for exposed `.env` or `.git/config` paths, missing HTTP security headers (`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`), and overly permissive CORS headers (`Access-Control-Allow-Origin: *`).
- **`orchestrator.py`**: Sequences the entire scanning and agent pipeline. Routes known git hosts (`github.com`, `gitlab.com`, `bitbucket.org`) or `.git` endpoints directly to cloning, attempts clone on ambiguous targets, and falls back to live scanning if cloning fails.

### AI Agent Layer

Located in `agents/`, this layer turns raw scanner outputs into human-readable, prioritized, and fixable insights:

1. **Triage Agent (`agents/triage_agent.py`)**:
   - Ingests raw findings from all scanners.
   - Deduplicates overlapping findings pointing to the same root cause.
   - Normalizes severities into four standard tiers: `critical`, `high`, `medium`, `low`.
   - Uses `gemini-3.8-flash` via the `google-genai` SDK.
   - Falls back gracefully to deterministic deduplication and rule-based severity assignment if `GEMINI_API_KEY` is not provided or the request fails.
2. **Explainer Agent (`agents/explainer_agent.py`)**:
   - Converts technical security alerts into plain English for vibe-coders and engineers without a security background.
   - Returns structured attributes: `what_it_means` (1-2 sentences) and `why_it_matters` (business & exploit consequence).
   - Falls back to built-in explanation templates by category when offline.
3. **Fix-Prompt Agent (`agents/fixprompt_agent.py`)**:
   - Builds copy-paste prompts formatted for AI coding tools (Lovable, Bolt, v0, Replit, Cursor, GitHub Copilot).
   - Adapts instructions dynamically based on the detected platform:
     - **Lovable / Supabase**: Row Level Security policies, `auth.uid()`, Supabase secrets management.
     - **Replit**: Guides secrets directly to Replit Secrets manager instead of `.env` files.
     - **Bolt / v0**: Accounts for framework variable scoping (Vite / Next.js client vs. server variables).
     - **Generic**: Standard file-targeted remediation recipes.
   - Falls back to templated fix prompts if the LLM is unavailable.
4. **Verify Agent (`agents/verify_agent.py`)**:
   - Performs deterministic diffing between previous scan findings and current rescan findings.
   - Identifies whether each issue is `"still_present"` or `"resolved"` with no LLM dependency and 100% reproducibility.

### Backend & Persistence Layer

Located in `backend/`:

- Built on **FastAPI** and **SQLAlchemy**.
- Exposes REST endpoints to create scans, fetch scan status/findings, execute rescans, and query badge statuses.
- Supports PostgreSQL in production (`postgresql+psycopg2://...`) and falls back to a local SQLite database (`secure_vibecode.db`) when `DATABASE_URL` is omitted.
- Auto-creates database schema on startup via `init_db()`.

### Frontend Web Application

Located in `frontend/`:

- Built with **Next.js** (App Router), **React**, **TypeScript**, and **Tailwind CSS**.
- Provides a clean user experience with light and dark mode support.
- Features real-time scan animation progress, detailed finding cards, copy-to-clipboard fix prompts, rescan execution, and status badge previews.
- Transparently persists the session `X-Owner-Token` in browser `localStorage` to retain scan ownership across refreshes.

### Detection Quality & Evaluation Suite

Located in `eval/`:

- **Ground Truth Test Set (`eval/test_set.py`)**: Curated benchmark suite containing real and synthetic vulnerable target apps with documented expected security findings across secrets, Supabase RLS, and CORS vulnerabilities.
- **Automated Evaluation Harness (`eval/evaluate.py`)**: Executes full scanner engine against the benchmark dataset and outputs per-repository and aggregate precision, recall, and F1 accuracy scores via `pandas`.
- **Evaluation Methodology (`eval/EVALUATION.md`)**: Complete write-up detailing the benchmark dataset, entropy threshold equations, and empirical accuracy findings for presentation and pitch credibility.

---

## Environment Configuration

Copy `.env.example` to `.env` in the project root:

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `GEMINI_API_KEY` | Optional | *None* | Google Gemini API key used by the Triage, Explainer, and Fix-Prompt agents. If unset, built-in heuristic fallbacks run automatically. |
| `DATABASE_URL` | Optional | `sqlite:///./secure_vibecode.db` | Database connection string. For PostgreSQL, use the `postgresql+psycopg2://` scheme. |
| `ALLOWED_ORIGINS` | Optional | `http://localhost:3000,http://127.0.0.1:3000` | Comma-separated list of origins allowed by FastAPI CORS middleware. |
| `NEXT_PUBLIC_API_URL` | Optional | `http://localhost:8000` | Backend API base URL consumed by the Next.js frontend. |

---

## Installation & Local Setup

### Backend & CLI Setup

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd secure-vibecode
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On macOS / Linux / WSL:
   source venv/bin/activate
   # On Windows (Command Prompt):
   venv\Scripts\activate
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables** (optional if using SQLite and fallback heuristics):
   ```bash
   cp .env.example .env
   ```

5. **Start the FastAPI server**:
   ```bash
   uvicorn backend.main:app --reload --port 8000
   ```
   Interactive OpenAPI documentation will be available at [http://localhost:8000/docs](http://localhost:8000/docs).

### Frontend Setup

1. **Navigate to the frontend directory**:
   ```bash
   cd frontend
   ```

2. **Install Node dependencies**:
   ```bash
   npm install
   ```

3. **Run the Next.js development server**:
   ```bash
   npm run dev
   ```

4. Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Running Scans via CLI

You can run scans directly from your terminal without launching the web server or frontend:

```bash
# Scan a public GitHub / GitLab / Bitbucket repository
python run_scan.py https://github.com/example/my-repo

# Scan a live deployed web app (no source code required)
python run_scan.py https://my-app.vercel.app
```

The CLI prints structured JSON output containing detected platform, triaged findings, severity scores, explanations, and fix prompts.

---

## Running Scanner Evaluation Harness

To measure the detection precision and recall of the scanner pipeline against the ground truth benchmark test set, run:

```bash
python -m eval.evaluate
```

This runs the scanners against all test repositories and outputs a pandas summary table showing True Positives (TP), False Positives (FP), False Negatives (FN), Precision, Recall, and overall F1 Score.

---

## API Reference & Ownership Model

### Ownership Model (No Passwords, Session Token Based)

- `POST /scans` generates a unique ownership token (`uuid4`) returned via the `X-Owner-Token` HTTP response header. If an existing `X-Owner-Token` request header is provided (e.g. from the same client session), it is preserved.
- `GET /scans/{id}`, `POST /scans/{id}/rescan`, and `GET /scans/{id}/badge` require the matching `X-Owner-Token` request header.
- Requests with missing or incorrect tokens return `404 Not Found` (rather than `403 Forbidden`) so unauthenticated clients cannot discover whether a scan ID exists.

### Endpoints

| Method | Path | Description | Required Headers |
|---|---|---|---|
| `POST` | `/scans` | Initiates a new scan against a target URL and persists it | `Content-Type: application/json`, optional `X-Owner-Token` |
| `GET` | `/scans/{id}` | Retrieves scan details and its findings | `X-Owner-Token: <token>` |
| `POST` | `/scans/{id}/rescan` | Runs a rescan, updates existing findings, resolves fixed issues | `X-Owner-Token: <token>` |
| `GET` | `/scans/{id}/badge` | Returns pass/fail badge status (`fail` if any open critical/high) | `X-Owner-Token: <token>` |

### Example cURL Commands

```bash
# 1. Create a scan (inspect response headers with -i to view X-Owner-Token)
curl -i -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://github.com/example/lovable-app"}'

# 2. Fetch the scan
curl http://localhost:8000/scans/<SCAN_ID> \
  -H "X-Owner-Token: <TOKEN>"

# 3. Rescan after applying fixes
curl -X POST http://localhost:8000/scans/<SCAN_ID>/rescan \
  -H "X-Owner-Token: <TOKEN>"

# 4. Check badge verification status
curl http://localhost:8000/scans/<SCAN_ID>/badge \
  -H "X-Owner-Token: <TOKEN>"
```

*(You can also use `requests.http` directly in VS Code with the REST Client extension.)*

---

## Testing

Run the test suite using `pytest`:

```bash
# Run all tests
python -m pytest -v

# Run API and persistence tests
python -m pytest tests/test_api.py -v

# Run AI agent contract and triage tests
python -m pytest tests/test_agents.py -v
```

Tests use temporary SQLite databases and deterministic mock scanners, ensuring tests run reliably offline and without API keys.

---

## Deployment Guide

### Deploying Backend to Railway

1. Push your repository to GitHub.
2. In [Railway](https://railway.app/), select **New Project** -> **Deploy from GitHub repo**.
3. Set the **Root Directory** to the repository root `/` (do not set to `/backend`, as backend imports scanners and agents from the root).
4. Add the **PostgreSQL** database plugin in Railway. This automatically provisions Postgres and sets `DATABASE_URL`.
5. Configure environment variables in Railway:
   - `DATABASE_URL`: Injected automatically by the PostgreSQL plugin.
   - `ALLOWED_ORIGINS`: Set to your deployed frontend domain (e.g. `https://secure-vibecode.vercel.app`).
   - `GEMINI_API_KEY`: Your Google AI Studio API key.
6. Railway automatically uses the root `Procfile` (`web: uvicorn backend.main:app --host 0.0.0.0 --port $PORT`).

### Deploying Frontend to Vercel

1. In [Vercel](https://vercel.com/), import the repository.
2. Set the **Root Directory** to `frontend`.
3. Set the build environment variable:
   - `NEXT_PUBLIC_API_URL`: The public URL of your Railway backend service (e.g. `https://web-production-xxxx.up.railway.app`).
4. Deploy the application.

---

## Design Decisions & Roadmap

- **Deterministic Fallbacks**: Every AI agent includes a deterministic fallback path, allowing scans, triaging, and fix-prompt generation to function without external LLM availability.
- **Stateless Ownership**: Token-based ownership avoids login hurdles for fast hackathon onboarding while maintaining private scan results.
- **V2 Roadmap Candidates**:
  - Asynchronous background task workers (Celery/RQ) with progress webhooks for large repositories.
  - Multi-user team workspaces and shared organization dashboards.
  - Deeper framework integrations (Cursor rules generator, GitHub Action security gate).
