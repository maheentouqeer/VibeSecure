"""Evaluation test set containing ground truth vulnerabilities for target repositories.

Includes synthetic local/remote benchmark repositories with known, documented findings
for measuring security scanner precision, recall, and overall F1 accuracy, as well as
evaluating agent-layer platform-awareness and anti-hallucination grounding.
"""

from typing import Any, TypedDict


class ExpectedFinding(TypedDict):
    category: str
    file: str
    label_contains: str | None


class TestRepoSpec(TypedDict):
    id: str
    name: str
    description: str
    url: str | None  # Remote Git repo URL if applicable
    platform: str
    expected_findings: list[ExpectedFinding]


# Curated Ground Truth Test Benchmark Dataset
TEST_SET: list[TestRepoSpec] = [
    {
        "id": "synthetic_vulnerable_app_1",
        "name": "Vulnerable Lovable Supabase Starter",
        "description": "Repo with unhandled RLS policy, exposed AWS key, and hardcoded JWT bearer key.",
        "url": None,  # evaluated locally/mocked
        "platform": "lovable_supabase",
        "expected_findings": [
            {
                "category": "hardcoded_secret",
                "file": "src/config/aws.ts",
                "label_contains": "AWS Access Key",
            },
            {
                "category": "hardcoded_secret",
                "file": "src/lib/auth.ts",
                "label_contains": "High Entropy Secret",
            },
            {
                "category": "missing_access_control",
                "file": "supabase migrations",
                "label_contains": "Row-Level Security not enabled",
            },
        ],
    },
    {
        "id": "synthetic_vulnerable_app_2",
        "name": "Vulnerable Bolt React Express App",
        "description": "Repo with Stripe test key in frontend code and open CORS endpoint.",
        "url": None,
        "platform": "bolt_v0",
        "expected_findings": [
            {
                "category": "hardcoded_secret",
                "file": "src/services/stripe.js",
                "label_contains": "Stripe Secret Key",
            },
            {
                "category": "cors_misconfig",
                "file": "server.js",
                "label_contains": None,
            },
        ],
    },
    {
        "id": "synthetic_vulnerable_app_3",
        "name": "Vulnerable Replit Python App",
        "description": "Replit project with hardcoded Google API token in server code.",
        "url": None,
        "platform": "replit",
        "expected_findings": [
            {
                "category": "hardcoded_secret",
                "file": "server.py",
                "label_contains": "Google API Key",
            },
        ],
    },
    {
        "id": "real_sample_vulnerable_repo",
        "name": "Sample Node Security Benchmark",
        "description": "GitHub sample repository testing secret leak and SQL injection patterns.",
        "url": "https://github.com/octocat/Spoon-Knife",
        "platform": "generic",
        "expected_findings": [],  # Clean repo benchmark (tests false positives)
    },
]
