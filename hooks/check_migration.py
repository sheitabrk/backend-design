#!/usr/bin/env python3
"""
Pre-write check for database migration files.

Scans migration files for the dangerous patterns from the migration-safety
skill and warns. Does NOT block. The point is to flag, not gate.

Triggers on file paths that look like migrations:
- contains "/migrations/" or "\\migrations\\"
- contains "/migrate/" or "\\migrate\\"
- contains "/alembic/" or "\\alembic\\"
- filename matches a typical migration prefix (V123__, 20240101_, 0001_, etc.)

Emits warnings as hook additionalContext on stdout, exits 0 (allow).
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _hook_io import emit_warning, read_write_or_edit, text_field  # noqa: E402


MIGRATION_PATH_PATTERNS = [
    re.compile(r"[\\/](migrations?|migrate|alembic|db[\\/]migrate|knex[\\/]migrations)[\\/]", re.IGNORECASE),
]

MIGRATION_FILENAME_PATTERNS = [
    re.compile(r"^V\d+__", re.IGNORECASE),
    re.compile(r"^\d{4,}[_-]"),
    re.compile(r"^\d{8,14}[_-]"),
]


DANGER_RULES = [
    {
        "name": "ALTER ... NOT NULL without DEFAULT",
        "pattern": re.compile(
            r"ALTER\s+TABLE\s+\S+\s+(?:ALTER\s+COLUMN\s+\S+\s+SET\s+NOT\s+NULL|ADD\s+COLUMN\s+\S+\s+\S+\s+NOT\s+NULL\s*(?!.*\bDEFAULT\b))",
            re.IGNORECASE | re.DOTALL,
        ),
        "why": "On large tables this takes an exclusive lock and rewrites every row. Split into 3 migrations: add nullable, backfill in a separate script, then SET NOT NULL.",
    },
    {
        "name": "DROP COLUMN",
        "pattern": re.compile(r"ALTER\s+TABLE\s+\S+\s+DROP\s+COLUMN\b", re.IGNORECASE),
        "why": "Drops break any service version still reading the column. Deprecate reads, deprecate writes, then drop in a separate deploy.",
    },
    {
        "name": "DROP TABLE",
        "pattern": re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
        "why": "Irreversible without backups. Confirm the table is no longer referenced anywhere and document the rollback plan in the PR description.",
    },
    {
        "name": "RENAME in one shot",
        "pattern": re.compile(r"ALTER\s+\S+\s+RENAME\s+", re.IGNORECASE),
        "why": "Breaks all app instances during a rolling deploy. Use add-new + dual-write + switch + drop-old across multiple migrations.",
    },
    {
        "name": "CREATE INDEX without CONCURRENTLY",
        "pattern": re.compile(r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY\b)", re.IGNORECASE),
        "why": "Locks writes on the table while building. Use `CREATE INDEX CONCURRENTLY` for any non-empty table.",
    },
    {
        "name": "ADD CONSTRAINT CHECK without NOT VALID",
        "pattern": re.compile(r"ADD\s+CONSTRAINT\s+\S+\s+CHECK\s*\((?:(?!NOT\s+VALID).)*\)\s*;?$", re.IGNORECASE | re.MULTILINE),
        "why": "Scans every row under a lock. Use `ADD CONSTRAINT ... CHECK (...) NOT VALID`, then `VALIDATE CONSTRAINT` in a later step.",
    },
    {
        "name": "Embedded data backfill (UPDATE/INSERT in migration)",
        "pattern": re.compile(r"^\s*(UPDATE|INSERT)\s+", re.IGNORECASE | re.MULTILINE),
        "why": "Long-running data changes inside a migration hold locks for the duration. Move to a separate, batched, restartable script.",
    },
]


def is_migration_path(path: str) -> bool:
    if not path:
        return False
    for pat in MIGRATION_PATH_PATTERNS:
        if pat.search(path):
            return True
    basename = os.path.basename(path)
    for pat in MIGRATION_FILENAME_PATTERNS:
        if pat.match(basename):
            return True
    return False


def extract_content(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Write":
        return text_field(tool_input, "content")
    if tool_name == "Edit":
        return text_field(tool_input, "new_string") + "\n" + text_field(tool_input, "old_string")
    return ""


def main() -> int:
    event = read_write_or_edit()
    if event is None:
        return 0
    tool_name, tool_input = event
    path = text_field(tool_input, "file_path")

    if not is_migration_path(path):
        return 0

    content = extract_content(tool_name, tool_input)
    if not content.strip():
        return 0

    findings = []
    for rule in DANGER_RULES:
        if rule["pattern"].search(content):
            findings.append(rule)

    if not findings:
        return 0

    lines = ["[backend-design] migration-safety review for {}".format(path)]
    for f in findings:
        lines.append("  - {}".format(f["name"]))
        lines.append("    {}".format(f["why"]))
    lines.append("  See: skills/migration-safety. Run `/backend-design:review-migration` for a full review.")
    emit_warning(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
