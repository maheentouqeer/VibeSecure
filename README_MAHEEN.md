# Secure-VibeCode — Maheen's Part (Core Scanning Engine + Orchestrator)

This is your scope only: the four scanners and the orchestrator that
sequences them. It runs completely on its own — no Streamlit, no
FastAPI, no Gemini API key needed — because the agent layer is
stubbed with plain Python placeholders instead of real LLM calls.

## What's in here

```
maheen-secure-vibecode/
  scanner/
    repo_utils.py             # clones a public GitHub repo to a temp dir, deletes it after
    platform_detector.py      # fingerprints Lovable/Supabase, Bolt/v0, Replit, or generic
    secrets_scanner.py        # regex-based hardcoded secret detection
    code_scanner.py           # wraps Semgrep's free rule packs
    supabase_rls_checker.py   # flags Supabase tables missing Row-Level Security
    live_scanner.py           # black-box checks on a live deployed URL
  agents/
    triage_agent.py           # STUB — Ali replaces the body later
    explainer_agent.py        # STUB — Ali replaces the body later
    fixprompt_agent.py        # STUB — Ali replaces the body later
    verify_agent.py           # REAL — plain Python diff, no LLM needed, nothing to replace
  orchestrator.py             # ties scanners + agents together — this is the shared interface
  run_scan.py                 # CLI to test everything end-to-end
  requirements-core.txt
```

## Setup

```bash
python -m venv venv
source venv/bin/activate          # WSL/Linux/Mac; use venv\Scripts\activate on plain Windows
pip install -r requirements-core.txt
```

Semgrep needs no extra setup beyond the pip install — the rule packs
(`p/security-audit`, `p/secrets`) download automatically on first run.

## Run it

```bash
# Scan a public GitHub repo
python run_scan.py https://github.com/someuser/some-public-repo

# Scan a live deployed app (no source access needed)
python run_scan.py https://some-deployed-app.vercel.app
```

You'll get a JSON dump of every finding, complete with a (templated,
not-yet-AI-generated) explanation and fix prompt — because the stub
agents produce real output shapes, just not real LLM reasoning yet.

## Testing your part before anyone else's code touches it

Try it against:
1. **A repo you know is clean** — should return an empty or near-empty `findings` list.
2. **A repo with an obvious hardcoded key** (paste a fake `AIzaSy...`-style string into a test file) — should show up under `hardcoded_secret`.
3. **A Supabase project's SQL migrations with a table missing `ENABLE ROW LEVEL SECURITY`** — should show up under `missing_access_control`.
4. **Any live URL** — try one of your own deployed apps to sanity-check the header/CORS/`.env` checks.

If all four behave as expected, your part is solid and ready to merge — regardless of whether Ali's agents exist yet.

## How this lets everyone else start immediately

This is the whole point of shipping stubs instead of waiting. Team is
5 people (Talha did not register for the hackathon, so the earlier
6-person split doesn't apply — Muqadas and Aneel keep the frontend and
deployment scope they originally had):

- **Ali** opens `agents/triage_agent.py`, `explainer_agent.py`, and `fixprompt_agent.py` and replaces only the function *bodies* with real Gemini calls — the function names, inputs, and outputs described in each file's docstring don't change, so he can develop and test his agents against your real scanners from day one, and `orchestrator.py` never needs to be touched.
- **Aneel** imports `from orchestrator import run_full_scan, rescan` into his FastAPI service immediately, and separately owns deploying that service to Railway (with the PostgreSQL plugin) once it's ready — he can build and test the whole persistence layer today without waiting for Ali.
- **Muqadas** owns the Next.js frontend (built via vibe-coding tools, since she's learning that) and its Vercel deployment. She does the same import pattern via the API Aneel exposes, and can build the full interface today — swapping in Ali's real agents later changes zero lines of frontend code, since the output shape never changes.
- **Zaki** can start his evaluation harness against this exact code today — his precision/recall numbers on the *scanners* will be valid immediately; only the explanation/fix-prompt quality scoring needs to wait for Ali's real agents.

## Merging later

When Ali's real agents are ready, only three files change:
`agents/triage_agent.py`, `agents/explainer_agent.py`,
`agents/fixprompt_agent.py`. Nobody else's code — not the orchestrator,
not Aneel's backend, not Muqadas's frontend — needs to change at all,
because everyone built against the same contract from the start.
