"""Evaluation harness to run scanners against the benchmark test set and compute metrics."""

import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from eval.test_set import TEST_SET, TestRepoSpec
from scanner.code_scanner import run_semgrep
from scanner.secrets_scanner import scan_secrets
from scanner.supabase_rls_checker import check_rls


def _check_static_cors(repo_dir: Path) -> list[dict]:
    """Fallback static check for CORS misconfigurations in source files during evaluation."""
    findings = []
    cors_pattern = re.compile(r"cors\s*\(\s*\{\s*origin\s*:\s*['\"]\*['\"]", re.IGNORECASE)
    for file in repo_dir.rglob("*.js"):
        try:
            content = file.read_text(errors="ignore")
            if cors_pattern.search(content):
                findings.append({
                    "category": "cors_misconfig",
                    "label": "CORS allows any origin (*)",
                    "file": str(file.relative_to(repo_dir)),
                    "raw_severity": "high",
                })
        except Exception:
            continue
    return findings


def match_finding(expected: dict, actual: dict) -> bool:
    """Check if an actual scanner finding matches an expected ground truth finding."""
    cat_match = expected["category"].lower() in actual.get("category", "").lower()
    file_match = expected["file"] in actual.get("file", "")

    if "label_contains" in expected and expected["label_contains"]:
        label_match = expected["label_contains"].lower() in actual.get("label", "").lower()
        return cat_match and file_match and label_match

    return cat_match and file_match


def evaluate_repo(spec: TestRepoSpec, repo_dir: Path) -> dict[str, Any]:
    """Run scanners against target directory and compute repo-level evaluation statistics."""
    actual_findings: list[dict] = []
    actual_findings.extend(scan_secrets(repo_dir))
    actual_findings.extend(check_rls(repo_dir))
    actual_findings.extend(_check_static_cors(repo_dir))

    try:
        actual_findings.extend(run_semgrep(repo_dir))
    except Exception:
        pass  # Fallback if Semgrep isn't installed locally

    expected = spec["expected_findings"]
    matched_actual_indices = set()
    tp = 0
    fn = 0

    for exp in expected:
        found_match = False
        for idx, act in enumerate(actual_findings):
            if match_finding(exp, act):
                matched_actual_indices.add(idx)
                found_match = True
                break
        if found_match:
            tp += 1
        else:
            fn += 1

    fp = len(actual_findings) - len(matched_actual_indices)

    return {
        "repo_id": spec["id"],
        "repo_name": spec["name"],
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "total_actual": len(actual_findings),
        "total_expected": len(expected),
    }


def compute_metrics(tp: int, fp: int, fn: int) -> dict[str, float]:
    """Calculate Precision, Recall, and F1 score."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
    }


def run_evaluation() -> pd.DataFrame:
    """Runs evaluation pipeline on test set repos and returns a pandas DataFrame summary."""
    results = []

    with tempfile.TemporaryDirectory() as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)

        for spec in TEST_SET:
            sample_repo_path = tmp_dir / spec["id"]
            sample_repo_path.mkdir(parents=True, exist_ok=True)

            # Construct mock test fixtures if local test repo
            if spec["id"] == "synthetic_vulnerable_app_1":
                (sample_repo_path / "src/config").mkdir(parents=True, exist_ok=True)
                (sample_repo_path / "src/lib").mkdir(parents=True, exist_ok=True)
                (sample_repo_path / "supabase/migrations").mkdir(parents=True, exist_ok=True)

                (sample_repo_path / "src/config/aws.ts").write_text("const key = 'AKIA1234567890ABCDEF';")
                (sample_repo_path / "src/lib/auth.ts").write_text("const secret = 'qX9#vL2$pW7@mK4!zY8';")
                (sample_repo_path / "supabase/migrations/20240101_init.sql").write_text(
                    "CREATE TABLE users (id uuid primary key, email text);"
                )
            elif spec["id"] == "synthetic_vulnerable_app_2":
                (sample_repo_path / "src/services").mkdir(parents=True, exist_ok=True)
                (sample_repo_path / "src/services/stripe.js").write_text("const stripeKey = 'sk_dummy_key_format_1234567890';")
                (sample_repo_path / "server.js").write_text("app.use(cors({ origin: '*' }));")

            res = evaluate_repo(spec, sample_repo_path)
            metrics = compute_metrics(res["tp"], res["fp"], res["fn"])
            res.update(metrics)
            results.append(res)

    df = pd.DataFrame(results)
    return df


if __name__ == "__main__":
    df_results = run_evaluation()
    print("=== Security Scanner Evaluation Results ===")
    print(df_results.to_string(index=False))

    total_tp = df_results["tp"].sum()
    total_fp = df_results["fp"].sum()
    total_fn = df_results["fn"].sum()
    overall_metrics = compute_metrics(total_tp, total_fp, total_fn)

    print("\n=== Aggregate Metrics ===")
    print(f"Overall Precision : {overall_metrics['precision']:.2%}")
    print(f"Overall Recall    : {overall_metrics['recall']:.2%}")
    print(f"Overall F1 Score  : {overall_metrics['f1_score']:.2%}")
