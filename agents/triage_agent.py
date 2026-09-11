"""STUB — placeholder for Ali's real Triage Agent (Gemini-based).

Purpose right now: let the scanner engine and orchestrator run and be
tested end-to-end today, without waiting on Ali's LLM work or a
Gemini API key.

CONTRACT — do not change without telling the team:
  input:  list of raw finding dicts (whatever shape a scanner produced)
  output: list of dicts, each with exactly these keys:
          id, category, label, file, severity
          (severity must be one of: critical, high, medium, low)

Aneel's backend and the Next.js frontend both depend on this exact
output shape, so Ali can swap the body of triage() for a real Gemini
call later without anyone else changing a line of their code.
"""

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def triage(raw_findings: list[dict]) -> list[dict]:
    """STUB: passes findings through with minimal cleanup instead of a
    real LLM-based dedupe/rank. Replace the body with a Gemini call
    that dedupes and re-ranks by real-world severity — keep the
    input/output shape described above."""
    result = []
    for i, f in enumerate(raw_findings):
        result.append({
            "id": f.get("id", f"finding_{i}"),
            "category": f.get("category", "unknown"),
            "label": f.get("label", "Unlabeled finding"),
            "file": f.get("file", ""),
            "severity": _SEVERITY_MAP.get(f.get("raw_severity", "medium"), "medium"),
        })
    return result
