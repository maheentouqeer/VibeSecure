"""Re-scan on demand. This is deliberately plain Python, not an LLM call --
diffing two finding lists is a deterministic task and doesn't need an
agent. Reserve LLM calls for genuinely ambiguous judgment (triage,
explaining, phrasing fixes); use plain code wherever a rule suffices.
"""


def diff_findings(previous: list[dict], current: list[dict]) -> list[dict]:
    current_labels = {(f["category"], f["label"], f.get("file")) for f in current}
    results = []
    for f in previous:
        key = (f["category"], f["label"], f.get("file"))
        status = "still_present" if key in current_labels else "resolved"
        results.append({**f, "status": status})
    return results
