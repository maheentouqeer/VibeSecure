"""Re-scan on demand. This is deliberately plain Python, not an LLM call --
diffing two finding lists is a deterministic task and doesn't need an
agent. Reserve LLM calls for genuinely ambiguous judgment (triage,
explaining, phrasing fixes); use plain code wherever a rule suffices.
"""
import hashlib
import re

# Volatile detail baked into some labels, e.g. "High Entropy Secret (entropy: 5.12)".
# It changes whenever the secret's value changes, so it must not be part of identity.
_VOLATILE_LABEL_DETAIL = re.compile(r"\s*\(entropy:[^)]*\)")


def fingerprint(finding: dict) -> str:
    """Stable identity for a finding across scans: category + label (minus
    volatile detail) + file + table. `table` keeps two tables that are both
    missing RLS from collapsing into one finding."""
    label = _VOLATILE_LABEL_DETAIL.sub("", str(finding.get("label", ""))).strip()
    file_path = str(finding.get("file") or "").replace("\\", "/").strip()
    parts = (str(finding.get("category", "")), label, file_path, str(finding.get("table") or ""))
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


def diff_findings(previous: list[dict], current: list[dict]) -> list[dict]:
    current_fingerprints = {fingerprint(f) for f in current}
    results = []
    for f in previous:
        status = "still_present" if fingerprint(f) in current_fingerprints else "resolved"
        results.append({**f, "status": status})
    return results
