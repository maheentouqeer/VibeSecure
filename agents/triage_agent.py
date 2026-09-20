"""Triage Agent (Gemini-based).

CONTRACT — do not change without telling the team:
input:  list of raw finding dicts (whatever shape a scanner produced)
output: list of dicts, each with exactly these keys:
        id, category, label, file, severity (plus 'table' if applicable).
        (severity must be one of: critical, high, medium, low)
"""
import json
import logging
import os
from typing import Any

from agents.privacy import PLACEHOLDER_NOTE, Masker

logger = logging.getLogger(__name__)

# Using the requested models (Note: these will trigger the fallback function)
MODELS = ("gemini-3.8-flash", "gemini-3.6-flash")

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
        dedupe_key = (cat, label, file_path, f.get("table"))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        
        raw_sev = str(f.get("raw_severity", "medium")).lower()
        severity = _SEVERITY_MAP.get(raw_sev, "medium")
        
        entry = {
            "id": f.get("id", f"finding_{i}"),
            "category": cat,
            "label": label,
            "file": file_path,
            "severity": severity,
        }
        if "table" in f:
            entry["table"] = f["table"]
            
        result.append(entry)
    return result


def triage(raw_findings: list[dict]) -> list[dict]:
    """Uses Gemini to deduplicate and rank raw findings by real-world security severity.
    Cascades through models before falling back gracefully if errors occur or key is unset.
    """
    if not raw_findings:
        return []

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logger.debug("GEMINI_API_KEY not set; using fallback triage.")
        return _fallback_triage(raw_findings)

    # One masker for the whole list, so the same file is the same placeholder in every finding.
    masker = Masker()
    safe_findings = [masker.mask_finding(f) for f in raw_findings]
    prompt = f"""You are an application security triage expert. Analyze the following list of raw scanner security findings:
{PLACEHOLDER_NOTE}
{json.dumps(safe_findings, indent=2)}

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
- "table": string (only if the matching input finding included a "table" field; omit otherwise)

Do not output markdown code fences or any extra commentary, only valid JSON.
"""

    # Safety net: some findings (e.g. missing Row-Level Security) carry a
    # "table" field the fix-prompt agent needs later. The model is asked
    # to preserve it, but in case it doesn't, back-fill it here by
    # matching on (category, label, file) against the original input.
    table_lookup = {
        (f.get("category"), f.get("label"), f.get("file")): f["table"]
        for f in raw_findings
        if "table" in f
    }

    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        
        for model in MODELS:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                )
                
                text = (response.text or "").strip()
                if text.startswith("```"):
                    lines = text.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    text = "\n".join(lines).strip()
                    
                parsed = json.loads(text)
                
                if isinstance(parsed, list):
                    if any(masker.unresolved(v) for item in parsed if isinstance(item, dict) for v in item.values() if isinstance(v, str)):
                        logger.warning("Model %s used a placeholder we cannot resolve; ignoring its answer", model)
                        continue
                    parsed = [masker.restore_finding(item) if isinstance(item, dict) else item for item in parsed]
                    sanitized = []
                    for i, item in enumerate(parsed):
                        if not isinstance(item, dict):
                            continue
                            
                        sev = str(item.get("severity", "medium")).lower()
                        if sev not in _VALID_SEVERITIES:
                            sev = "medium"
                            
                        category = str(item.get("category", "unknown"))
                        label = str(item.get("label", "Unlabeled finding"))
                        file_path = str(item.get("file", ""))
                        
                        entry = {
                            "id": str(item.get("id", f"finding_{i}")),
                            "category": category,
                            "label": label,
                            "file": file_path,
                            "severity": sev,
                        }
                        
                        table = item.get("table") or table_lookup.get((category, label, file_path))
                        if table:
                            entry["table"] = table
                            
                        sanitized.append(entry)
                        
                    if sanitized:
                        return sanitized
                        
                logger.warning("Model %s returned unexpected output structure: %s", model, text)
                
            except Exception as model_err:
                logger.warning("Error during triage generation with model %s: %s", model, model_err)
                continue
                
    except Exception as err:
        logger.warning("Failed to initialize or execute Gemini client for triage: %s", err)
        
    return _fallback_triage(raw_findings)
