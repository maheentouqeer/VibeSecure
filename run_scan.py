"""Standalone test runner for the scanning engine + orchestrator.

No Streamlit, no FastAPI, no Gemini API key required — this exists so
you can verify your part works correctly on its own, before anyone
else's piece is wired in.

Usage:
    python run_scan.py https://github.com/someuser/some-public-repo
    python run_scan.py https://your-deployed-app.vercel.app
"""
import json
import sys

from orchestrator import run_full_scan


def main():
    if len(sys.argv) != 2:
        print("Usage: python run_scan.py <github-repo-url-or-live-app-url>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"Scanning {target} ...\n")
    result = run_full_scan(target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
