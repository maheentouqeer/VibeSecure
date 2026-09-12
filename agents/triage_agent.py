"""Triage Agent (Gemini-based).

CONTRACT — do not change without telling the team:
  input:  list of raw finding dicts (whatever shape a scanner produced)
  output: list of dicts, each with exactly these keys:
          id, category, label, file, severity
          (severity must be one of: critical, high, medium, low)
"""

import json
import os
from typing import Any

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _fallback_triage(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for i, f in enumerate(raw_findings):
        cat = f.get("category", "unknown")
        label = f.get("label", "Unlabeled finding")
        file_path = f.get("file", "")
        dedupe_key = (cat, label, file_path)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        raw_sev = str(f.get("raw_severity", "medium")).lower()
        severity = _SEVERITY_MAP.get(raw_sev, "medium")
        result.append({
            "id": f.get("id", f"finding_{i}"),
            "category": cat,
            "label": label,
            "file": file_path,
            "severity": severity,
        })
    return result


def triage(raw_findings: list[dict]) -> list[dict]:
    """Uses Gemini to deduplicate and rank raw findings by real-world security severity.
    Falls back gracefully if the API key is not configured or an error occurs.
    """
    if not raw_findings:
        return []

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return _fallback_triage(raw_findings)

    prompt = f"""You are an application security triage expert.
Analyze the following list of raw scanner security findings:
{json.dumps(raw_findings, indent=2)}

Tasks:
1. Deduplicate findings that point to the exact same core vulnerability.
2. Normalize and assess real-world exploitability and impact.
3. Assign severity: exactly one of "critical", "high", "medium", or "low".
4. Maintain or assign an "id" for each finding.

Return a strictly valid JSON array of objects. Each object MUST contain EXACTLY these keys:
- "id": string
- "category": string
- "label": string
- "file": string
- "severity": "critical" | "high" | "medium" | "low"

Do not output markdown code fences or any extra commentary, only valid JSON.
"""

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        text = response.text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        parsed = json.loads(text)
        if isinstance(parsed, list):
            sanitized = []
            for i, item in enumerate(parsed):
                if not isinstance(item, dict):
                    continue
                sev = str(item.get("severity", "medium")).lower()
                if sev not in _VALID_SEVERITIES:
                    sev = "medium"
                sanitized.append({
                    "id": str(item.get("id", f"finding_{i}")),
                    "category": str(item.get("category", "unknown")),
                    "label": str(item.get("label", "Unlabeled finding")),
                    "file": str(item.get("file", "")),
                    "severity": sev,
                })
            if sanitized:
                return sanitized
    except Exception:
        pass

    return _fallback_triage(raw_findings)
