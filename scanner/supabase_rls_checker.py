"""Flags Supabase tables that were created without Row-Level Security.

This is *the* single most common vibe-coding vulnerability (Lovable/
Bolt/Base44 apps built on Supabase ship with RLS off by default unless
explicitly enabled). Detection strategy: find every `create table`
statement in SQL migration files, and flag any table name that never
appears next to an `enable row level security` statement.
"""
import re
from pathlib import Path

CREATE_TABLE = re.compile(r"create\s+table\s+(?:if not exists\s+)?[\"']?(\w+)[\"']?", re.IGNORECASE)
ENABLE_RLS = re.compile(r"alter\s+table\s+[\"']?(\w+)[\"']?\s+enable\s+row\s+level\s+security", re.IGNORECASE)


def check_rls(repo_path: Path) -> list[dict]:
    sql_files = list(repo_path.rglob("*.sql"))
    if not sql_files:
        return []

    created_tables = set()
    rls_enabled_tables = set()

    for file in sql_files:
        try:
            text = file.read_text(errors="ignore")
        except Exception:
            continue
        created_tables.update(m.group(1) for m in CREATE_TABLE.finditer(text))
        rls_enabled_tables.update(m.group(1) for m in ENABLE_RLS.finditer(text))

    unprotected = created_tables - rls_enabled_tables
    return [
        {
            "category": "missing_access_control",
            "label": "Row-Level Security not enabled",
            "file": "supabase migrations",
            "table": table,
            "raw_severity": "critical",
        }
        for table in unprotected
    ]
