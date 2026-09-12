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
- Python 3.11+
- Node.js 18+ (for the frontend)
- Semgrep (optional, for static analysis scanning: `pip install semgrep`)

### Backend Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set up your environment variables in a `.env` file:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   DATABASE_URL=sqlite:///./secure_vibecode.db
   ALLOWED_ORIGINS=http://localhost:3000
   ```
3. Run the FastAPI server:
   ```bash
   uvicorn backend.main:app --reload --port 8000
   ```

### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```
4. Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Running Evaluations

To measure the precision, recall, and F1 score of the scanner suite against the curated ground-truth test benchmark dataset:

```bash
python -m eval.evaluate
```

---

## Running Tests

To run the deterministic agent and API test suites:

```bash
pytest
```
