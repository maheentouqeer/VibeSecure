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
For Linux Users: 
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
