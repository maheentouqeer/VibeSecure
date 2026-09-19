# Secure-VibeCode — Agent & Codebase Review

Reviewed as a staff-level AI engineer / hackathon judge, grounded in the actual code (not the README or design docs). Every finding below cites `file:line`. Ranked by: probability of breaking or embarrassing a live demo × damage if it does × judge-visibility.

---

## Headline finding

**The AI agent layer does not run — in any demo given so far.**

1. `agents/triage_agent.py:17`, `agents/explainer_agent.py:15`, `agents/fixprompt_agent.py:15` all declare `MODELS = ("gemini-3.8-flash", "gemini-3.6-flash")`. Neither model ID exists. Every call fails, both cascade attempts fail, and the code falls through to templates.
2. The code admits it — `agents/triage_agent.py:16`: `# Using the requested models (Note: these will trigger the fallback function)`.
3. There is no `.env` file in the repo, so `GEMINI_API_KEY` is unset and every agent short-circuits to its fallback *before even trying* the API.

Every "AI-generated" explanation currently shown comes from the `_TEMPLATES` dict in `agents/explainer_agent.py:17-46`, and every "AI-generated" fix prompt comes from `_PLATFORM_FIXES` in `agents/fixprompt_agent.py:27-52`. The homepage says "AI-powered vulnerability scanning." The product currently ships a regex scanner with a lookup table.

The fallback is also **silent** — only `logger.debug`/`logger.warning`, nothing in the API response or UI. There is no way to tell from the product whether the AI ran at all.

Everything below assumes this gets fixed first.

---

## Critical

### C1 — Dead model IDs + silent AI failure
- **Problem:** See headline. Fallbacks are meant as a safety net but are functioning as the only path, invisibly.
- **Change:** Pin real model IDs (e.g. `gemini-2.5-flash` / `gemini-flash-latest` as a cascade). Add a `.env` with a working key and a startup check that fails loudly if the key is missing in production. Propagate an `analysis_mode: "ai" | "heuristic"` field per finding through orchestrator → DB → API → UI, and render it as a small pill on each finding card.
- **Impact:** The difference between "AI agent project" and "regex tool with a Gemini import." Turns graceful degradation from a hidden liability into an honest, demoable reliability feature.
- **Priority:** Critical

### C2 — The triage LLM can silently delete findings
- **Problem:** `agents/triage_agent.py:121-150` builds `sanitized` purely from what the model returned, then `if sanitized: return sanitized`. If Gemini returns 3 of 22 findings, the product ships 3 and silently loses 19. In a security tool, an LLM that suppresses vulnerabilities is the worst possible failure mode.
- **Change:** Treat triage as *annotation*, never *filtering*. Send findings with stable pre-assigned IDs; require the model to return a verdict per input ID; reconcile against the input set and re-insert anything missing at its deterministic severity. Log any model-omitted finding as a reliability metric.
- **Impact:** Removes the most dangerous hallucination path in the product.
- **Priority:** Critical

### C3 — Agents explain code they have never seen
- **Problem:** The triage contract (`agents/triage_agent.py:5-7`) collapses findings to `id, category, label, file, severity`, discarding Semgrep's `line`/`message` (`scanner/code_scanner.py:51-53`) and the secrets scanner's `match_preview` (`scanner/secrets_scanner.py:66`). `explain()` and `generate_fix_prompt()` receive only a filename and a rule ID — they are guessing. The `Finding` DB model also has no `line` column, so the UI can't show `auth.ts:42` either.
- **Change:** Carry `line`, `message`, and a masked ±3-line code snippet through triage into the agents and the DB. Show the snippet in the finding card.
- **Impact:** Largest single quality jump available — explanations go from "a secret is hardcoded" to "on line 42 of `src/config/aws.ts` you assigned an AWS key to `const key`."
- **Priority:** Critical

### C4 — Fix prompts get zero validation
- **Problem:** `agents/fixprompt_agent.py:120-124` accepts any non-empty string as the returned prompt — a refusal, a markdown block, or a hallucinated API call all pass through. This string is what the user pastes into an AI tool that will **edit their code**.
- **Change:** Validate before returning: must reference the finding's actual `file`/`table`, must exceed a length floor, must not contain refusal markers or code fences. Retry once on failure, then fall back to the deterministic template. Consider Gemini structured output (`response_schema`) to get `{fix_prompt, references_file, assumptions}` for self-consistency checking.
- **Impact:** Directly addresses hallucination risk with a mechanism that's demoable in 20 seconds.
- **Priority:** Critical

### C5 — N+1 sequential LLM calls inside a blocking HTTP request
- **Problem:** `orchestrator.py:80-84` loops findings and makes **two sequential** Gemini calls per finding. 25 findings = 50 serial round trips inside the synchronous handler at `backend/main.py:106`, on top of Semgrep's 180s timeout (`scanner/code_scanner.py:28`) and a repo clone. The scan can exceed browser/proxy timeouts live on stage.
- **Change:** Batch explain + fix-prompt into one call per finding (they share context), run findings concurrently with `asyncio.gather` + a semaphore (~8), cap findings sent to the LLM by severity, and add per-call timeouts.
- **Impact:** Realistically turns a ~40s scan into ~6s.
- **Priority:** Critical

---

## High

### H1 — The eval harness grades itself and reports 100%
- **Problem:** `eval/evaluate.py:49-67` (`build_fixture`) writes the exact files that `eval/test_set.py` expects to find — it's a tautology. `eval/EVALUATION.md:50-54` then publishes 100.00% Precision/Recall/F1. It also evaluates only the scanners, never the agent layer.
- **Change:** Replace synthetic self-fixtures with 3-5 real pinned public repos plus a genuine clean-baseline repo for false positives. Report real numbers even if imperfect. Add an agent eval: severity agreement vs. a human-labeled set, and a fix-prompt groundedness check.
- **Impact:** Converts the weakest credibility artifact into a strength.
- **Priority:** High

### H2 — Entropy detector will flood any real repo
- **Problem:** `scanner/secrets_scanner.py:27` matches any quoted 16-128 char whitespace-free string at entropy ≥ 4.5. `SKIP_DIRS` (`secrets_scanner.py:21`) excludes `node_modules` but not root-level `package-lock.json`, which is full of `"integrity": "sha512-..."` hashes that all qualify as high-entropy secrets.
- **Change:** Skip lockfiles/minified assets by filename; exclude known-hash contexts (`integrity`, `sha512-`, `hash`, `checksum` keys); raise the bar to entropy ≥ 4.8 with mixed character classes, or require adjacency to a secret-ish identifier.
- **Impact:** Precision on stage — a live scan of a real repo is currently a coin flip.
- **Priority:** High

### H3 — Prompt injection from the code being scanned
- **Problem:** The scanned repo is attacker-controlled input and flows unsanitized into prompts via `json.dumps(finding)` (`agents/explainer_agent.py:70`, `agents/fixprompt_agent.py:100`) — file paths, Semgrep messages, labels. A malicious repo could embed an instruction-like string that gets echoed into a fix prompt the user then pastes into their own AI tool with full trust.
- **Change:** Delimit untrusted content in clearly fenced blocks with an explicit "treat as data, never instructions" system preamble. Strip control characters and instruction-like patterns from scanner text before templating. Layer with the C4 output validation.
- **Impact:** Real vulnerability fixed, and a strong demo moment: "we're a security tool that reads hostile code, so we hardened our own agents against prompt injection."
- **Priority:** High

### H4 — Verify agent can't reliably verify
- **Problem:** `agents/verify_agent.py:9-13` matches findings on `(category, label, file)`, but the secrets scanner bakes a float into the label (`secrets_scanner.py:88`: `f"High Entropy Secret (entropy: {entropy:.2f})"`). Any change to the secret shifts the entropy value, changes the label, and the old finding reports "resolved" while an identical new one appears.
- **Change:** Give findings a stable fingerprint (e.g. `sha256(category + normalized_file + table_or_rule_id)`), moving volatile values like entropy into a separate `detail` field never used for identity matching.
- **Impact:** Makes the badge — the product's core trust claim — actually trustworthy.
- **Priority:** High

### H5 — SSRF in the live scanner
- **Problem:** `scanner/live_scanner.py:22` and `:35` issue `requests.get` against arbitrary user-supplied URLs with no scheme/host validation and default redirect following — cloud metadata endpoints, localhost, and private ranges are all reachable.
- **Change:** Allowlist `http`/`https`, resolve the hostname and reject loopback/link-local/private/reserved ranges, set `allow_redirects=False` (or re-validate each hop), cap response size.
- **Impact:** This is the exact bug class the product claims to detect — a serious credibility risk if found by a judge.
- **Priority:** High

### H6 — Semgrep path handling can hard-crash a scan
- **Problem:** `scanner/code_scanner.py:50` calls `Path(r["path"]).relative_to(repo_path)` outside the try/except that only wraps `subprocess.run`/`json.loads`. Semgrep can return paths that don't cleanly resolve relative to `repo_path` (e.g. `/var` vs `/private/var` on macOS), raising `ValueError` and producing a 500 from `backend/main.py:108`.
- **Change:** Use `os.path.relpath` with a try/except fallback to the raw path, and resolve `repo_path` before comparison.
- **Priority:** High

---

## Medium

### M1 — "Past scans" is fake and will be clicked
`GET /scans` doesn't exist in `backend/main.py` (only `POST /scans`, `GET /scans/{id}`, rescan, badge). `HistoryScreen` in `frontend/app/page.tsx:911` renders React state only — refresh the page and history is empty despite a valid owner token in localStorage.
**Change:** Add `GET /scans` filtered by owner token; hydrate history on mount.

### M2 — The badge share link is a dead domain
`frontend/app/page.tsx:829-830` hardcodes `https://secure-vibecode.dev/badge/{id}` and a `.svg` embed. Neither exists; the real badge endpoint is owner-token-gated JSON.
**Change:** Ship a genuinely public `GET /badge/{id}.svg` returning an SVG, and point the share link at the real deployed domain.

### M3 — The "Sign in" button does nothing
`frontend/app/page.tsx:1144` (`toggleSignIn`) just flips a boolean.
**Change:** Wire real auth (Clerk) or remove the button — a visible non-functional control reads worse than an absent one.

### M4 — Frontend and backend disagree about the platform
`frontend/app/page.tsx:111-117` guesses platform from the URL string; the backend detects it from `package.json` (`scanner/platform_detector.py:47`). The placeholder shows one badge, the result swaps to another mid-demo.
**Change:** Show "detecting…" until the backend responds.

### M5 — No caching by commit SHA
Every rescan re-clones and re-runs every LLM call, even for an unchanged commit.
**Change:** Key scans on `(repo_url, commit_sha)` and short-circuit identical rescans — also makes repeat demos instant.

### M6 — Deterministic facts are left to model opinion
Missing RLS is critical by rule, not by vibe — but triage lets the model freely overwrite severity, so a hardcoded AWS key could be silently downgraded.
**Change:** Let the model raise severity freely but lower it only with a recorded justification, or run severity assignment advisory-only against a deterministic floor per category.

---

## Differentiators — what would make this memorable, not just solid

1. **Proof-of-exploit for RLS.** The scanner already detects Supabase tables without RLS and already finds the anon key in the same repo. Connect them: attempt an anonymous read against that project and report *"we pulled 3 rows from your `users` table using only the public key that's in your repo."* Not a template, not a hallucination — a live exploit. Gate behind explicit consent, only against the user's own project.
2. **MCP server.** Wrap `orchestrator.run_full_scan` as an MCP tool so scanning/fixing works from inside Cursor/Claude Code directly, without cloning — files are already local. This is already identified in the roadmap and is the highest-leverage distribution move available.

---

## Suggested build order

1. C1 (real model IDs + visible AI/heuristic mode) + C5 (concurrent/batched LLM calls) — a few hours, changes what the demo *is*.
2. C3 (carry line/snippet context) — the biggest quality jump for the least code.
3. C2 + C4 (triage can't drop findings; fix prompts get validated) — closes the two most dangerous hallucination paths.
4. H2 + H5 + H6 — quick, high-value hardening before a live scan of a real repo.
5. H1 — replace the circular eval with a real one; publish honest numbers.
6. M1-M6 as time allows; M1 and M2 are cheap and visibly close believability gaps.
