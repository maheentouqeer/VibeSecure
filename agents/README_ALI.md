# Secure-VibeCode — Ali's Part (AI Agent Layer)

This document outlines the scope, architecture, and implementation completed by **Ali** for the AI Agent layer located in `agents/`.

---

## Overview

The AI agent layer sits directly between the scanner engine and the orchestrator output. It processes raw findings from Semgrep, regex secret scanners, Supabase RLS checks, and live black-box endpoint tests, transforming raw technical warnings into actionable guidance for developers and vibe-coding assistants.

The layer consists of three LLM-powered agents and one deterministic verification engine:
1. **Triage Agent** (`agents/triage_agent.py`)
2. **Explainer Agent** (`agents/explainer_agent.py`)
3. **Fix-Prompt Agent** (`agents/fixprompt_agent.py`)
4. **Verify Agent** (`agents/verify_agent.py`)

---

## Detailed Agent Implementation

### 1. Triage Agent (`agents/triage_agent.py`)

- **Role**:
  - Ingests all raw finding dictionaries from the four scanners.
  - Deduplicates repeated findings pointing to the same root issue.
  - Re-ranks and normalizes severity into standard tiers based on real-world impact and exploitability.
- **Model**: `gemini-3.8-flash` using the official `google-genai` SDK.
- **Contract Adherence**:
  - **Input**: `raw_findings: list[dict]`
  - **Output**: `list[dict]` where every dictionary has strictly:
    - `id`: str
    - `category`: str
    - `label`: str
    - `file`: str
    - `severity`: `"critical"` | `"high"` | `"medium"` | `"low"`
- **Fallback Strategy**:
  - If `GEMINI_API_KEY` is unset or an API/JSON error occurs, deterministic deduplication and rule-based severity mapping (`critical`, `high`, `medium`, `low`) run automatically without crashing.

---

### 2. Explainer Agent (`agents/explainer_agent.py`)

- **Role**:
  - Generates clear, non-jargon, plain-English explanations targeted at vibe-coders and non-security engineers.
  - Focuses on real-world impact rather than abstract vulnerability theory.
- **Model**: `gemini-3.8-flash` using `google-genai`.
- **Contract Adherence**:
  - **Input**: Single finding dictionary (post-triage).
  - **Output**: A dictionary with strictly two keys:
    - `what_it_means`: str (concise 1-2 sentence description)
    - `why_it_matters`: str (practical consequences and risk in 1-2 sentences)
- **Fallback Strategy**:
  - Falls back to built-in explanation templates mapped by vulnerability category if the Gemini call is unavailable.

---

### 3. Fix-Prompt Agent (`agents/fixprompt_agent.py`)

- **Role**:
  - Constructs copy-paste ready fix prompts optimized for modern vibe-coding AI assistants (such as Lovable, Bolt, v0, Replit, Cursor, and GitHub Copilot).
  - Adapts instructions dynamically based on the detected target platform:
    - **Lovable / Supabase**: Instructs on Row Level Security (RLS) policies, `auth.uid()`, and Supabase vault/secrets.
    - **Replit**: Guides secrets directly to the Replit Secrets manager instead of `.env` files.
    - **Bolt / v0**: Accounts for framework environment variables (e.g. Next.js / Vite client vs server variable scoping).
    - **Generic**: Standard remediation recipes targeting the affected file.
- **Model**: `gemini-3.8-flash` using `google-genai`.
- **Contract Adherence**:
  - **Input**: Single finding dictionary (post-explain) and `platform: str`.
  - **Output**: Single prompt string.
- **Fallback Strategy**:
  - Automatically formats structured fallback instructions using predefined remediation templates if Gemini is unreachable.

---

### 4. Verify Agent (`agents/verify_agent.py`)

- **Role**:
  - Performs deterministic diffing of previous scan findings against current rescan findings.
  - Flags findings as either `"still_present"` or `"resolved"`.
- **Design Decision**:
  - Pure deterministic Python implementation. No LLM calls are used, ensuring 100% reproducible and zero-cost re-scans.

---

## API Keys & Environment Configuration

### Key Count
- **Exactly 1 API key** is needed across all agents: `GEMINI_API_KEY`.

### Setup
1. Generate an API key in [Google AI Studio](https://aistudio.google.com/).
2. Set the environment variable:

**Linux / macOS / WSL:**
```bash
export GEMINI_API_KEY="AIzaSy..."
```

**Windows (Command Prompt):**
```cmd
set GEMINI_API_KEY=AIzaSy...
```

**Windows (PowerShell):**
```powershell
$env:GEMINI_API_KEY="AIzaSy..."
```

---

## Testing & Verification

Run an end-to-end scan using the CLI runner:

```bash
# Scan a GitHub repository
python run_scan.py https://github.com/someuser/repo

# Scan a live deployment URL
python run_scan.py https://some-app.vercel.app
```

The system runs seamlessly both with and without `GEMINI_API_KEY` due to the graceful fallback architecture.
