#!/usr/bin/env python3
"""
Pre-write check for database migration files.

Scans migration files for the dangerous patterns from the migration-safety
skill and warns Claude. Does NOT block. The point is to flag, not gate.

Triggers on code or SQL files that look like migrations:
- under "migrations/", "migrate/" or "alembic/"
- SQL files with a typical migration prefix (V123__, 20240101_, 0001_, etc.)

For an Edit, only findings that the edit introduces are reported.

This is a regex heuristic, not a SQL parser. A quiet result is not a safety
guarantee; use a real migration linter for that.
"""

import collections
import os
import re
import sys

from _hook_io import read_payload, text, warn


MIGRATION_EXTENSIONS = (
    ".sql", ".py", ".rb", ".js", ".ts", ".cjs", ".mjs", ".php",
    ".go", ".java", ".kt", ".cs", ".xml", ".yaml", ".yml",
)

MIGRATION_PATH_PATTERN = re.compile(r"[\\/](migrations?|migrate|alembic)[\\/]", re.IGNORECASE)

MIGRATION_FILENAME_PATTERNS = [
    re.compile(r"^V\d+__.*\.(sql|java)$", re.IGNORECASE),
    re.compile(r"^\d{4,}[_-].*\.sql$", re.IGNORECASE),
]

MAX_FILE_BYTES = 1_000_000

NAME = r'(?:"[^"]*"|`[^`]*`|\[[^\]]*\]|[\w$]+)(?:\s*\.\s*(?:"[^"]*"|`[^`]*`|\[[^\]]*\]|[\w$]+))*'

WHY = {
    "NOT NULL without DEFAULT": "ADD COLUMN ... NOT NULL fails on a non-empty table, and SET NOT NULL scans it under an exclusive lock. Add nullable, backfill in a separate script, then SET NOT NULL.",
    "DROP COLUMN": "Drops break any service version still reading the column. Deprecate reads, deprecate writes, then drop in a separate deploy.",
    "DROP TABLE": "Irreversible without backups. Confirm the table is no longer referenced anywhere and document the rollback plan in the PR description.",
    "RENAME in one shot": "Breaks all app instances during a rolling deploy. Use add-new + dual-write + switch + drop-old across multiple migrations.",
    "CREATE INDEX without CONCURRENTLY": "Locks writes on the table while building. Use `CREATE INDEX CONCURRENTLY` for any non-empty table.",
    "ADD CONSTRAINT CHECK without NOT VALID": "Scans every row under a lock. Use `ADD CONSTRAINT ... CHECK (...) NOT VALID`, then `VALIDATE CONSTRAINT` in a later step.",
    "Embedded data backfill (UPDATE/INSERT in migration)": "Long-running data changes inside a migration hold locks for the duration. Move to a separate, batched, restartable script.",
}


def is_migration_path(path):
    if not path.lower().endswith(MIGRATION_EXTENSIONS):
        return False
    if MIGRATION_PATH_PATTERN.search(path):
        return True
    basename = os.path.basename(path)
    return any(pat.match(basename) for pat in MIGRATION_FILENAME_PATTERNS)


def strip_sql_noise(sql):
    """Drop comments and empty out string literals, keeping quoted identifiers."""
    def replace(match):
        token = match.group(0)
        if token.startswith("'"):
            return "''"
        if token.startswith('"'):
            return token
        return " "

    return re.sub(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|--[^\n]*|/\*.*?\*/", replace, sql, flags=re.DOTALL)


def cut_at_string_end(piece):
    """Drop host-language code after the quote that closes the SQL string."""
    depth = 0
    for i, char in enumerate(piece):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth <= 0 and re.match(r"""(?:\"\"\"|'''|["'`])\s*\)""", piece[i:]):
            return piece[:i]
    return piece


def split_statements(content, is_sql):
    if is_sql:
        parts = content.split(";")
    else:
        # SQL embedded in code often has no ";". Also cut where the next
        # statement starts and where the string holding it closes.
        starts = (r"(?=\b(?:ALTER\s+(?:TABLE|TYPE|VIEW|SCHEMA|SEQUENCE)|CREATE\s+(?:UNIQUE\s+)?(?:INDEX|TABLE)|"
                  r"DROP\s+TABLE|RENAME\s+TABLE)\b)")
        parts = []
        for chunk in content.split(";"):
            for piece in re.split(starts, chunk, flags=re.IGNORECASE):
                parts.append(cut_at_string_end(piece))
    return [" ".join(part.split()) for part in parts if part.strip()]


def split_clauses(body):
    """Split the body of an ALTER TABLE on commas outside parentheses."""
    clauses, depth, start = [], 0, 0
    for i, char in enumerate(body):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            clauses.append(body[start:i])
            start = i + 1
    clauses.append(body[start:])
    return [c.strip() for c in clauses if c.strip()]


def outside_parentheses(clause):
    previous = None
    while previous != clause:
        previous, clause = clause, re.sub(r"\([^()]*\)", " ", clause)
    return clause


def check_clause(clause):
    def starts(pattern):
        return re.match(pattern, clause, re.IGNORECASE)

    if starts(r"RENAME\b(?!\s+(?:CONSTRAINT|INDEX|KEY)\b)"):
        yield "RENAME in one shot"
    if starts(r"DROP\s+(?:COLUMN\b|(?!(?:CONSTRAINT|DEFAULT|NOT|IDENTITY|EXPRESSION|INDEX|KEY|PRIMARY|"
              r"FOREIGN|CHECK|PARTITION|STATISTICS|OIDS)\b)[\w\"`\[])"):
        yield "DROP COLUMN"
    if starts(r"ALTER\s+(?:COLUMN\s+)?\S+\s+SET\s+NOT\s+NULL\b"):
        yield "NOT NULL without DEFAULT"
    if starts(r"ADD\s+(?!(?:CONSTRAINT|PRIMARY|UNIQUE|FOREIGN|CHECK|EXCLUDE|INDEX|KEY|FULLTEXT|SPATIAL|PARTITION)\b)"):
        bare = outside_parentheses(clause)
        if (re.search(r"\bNOT\s+NULL\b", bare, re.IGNORECASE)
                and not re.search(r"\b(?:DEFAULT|GENERATED|(?:SMALL|BIG)?SERIAL)\b", bare, re.IGNORECASE)):
            yield "NOT NULL without DEFAULT"
    if starts(r"ADD\s+(?:CONSTRAINT\s+\S+\s+)?CHECK\b") and not re.search(r"\bNOT\s+VALID\b", clause, re.IGNORECASE):
        yield "ADD CONSTRAINT CHECK without NOT VALID"


def scan(content, is_sql):
    """Return a Counter of (rule, offending text)."""
    if is_sql:
        content = strip_sql_noise(content)
    findings = collections.Counter()
    statements = split_statements(content, is_sql)

    # An index on a table created in this same file locks nothing in use.
    created = {
        m.group(1).lower()
        for s in statements
        for m in re.finditer(r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(" + NAME + ")", s, re.IGNORECASE)
    }

    for statement in statements:
        alter = re.search(r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(" + NAME + r")\s*\*?\s*(.*)",
                          statement, re.IGNORECASE)
        if alter:
            for clause in split_clauses(alter.group(2)):
                for rule in check_clause(clause):
                    findings[(rule, alter.group(1) + " " + clause)] += 1

        if (re.search(r"\bALTER\s+(?:TYPE|VIEW|MATERIALIZED\s+VIEW|SCHEMA|SEQUENCE)\s+(?:IF\s+EXISTS\s+)?"
                      + NAME + r"\s+RENAME\b", statement, re.IGNORECASE)
                or re.search(r"\bRENAME\s+TABLE\b", statement, re.IGNORECASE)):
            findings[("RENAME in one shot", statement)] += 1

        if re.search(r"\bDROP\s+TABLE\b", statement, re.IGNORECASE):
            findings[("DROP TABLE", statement)] += 1

        if re.search(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b(?!\s+CONCURRENTLY\b)", statement, re.IGNORECASE):
            on = re.search(r"\bON\s+(?:ONLY\s+)?(" + NAME + ")", statement, re.IGNORECASE)
            if not (on and on.group(1).lower() in created):
                findings[("CREATE INDEX without CONCURRENTLY", statement)] += 1

    for match in re.finditer(r"^[ \t]*(?:UPDATE\s+(?:ONLY\s+)?\S+(?:\s+(?:AS\s+)?\w+)?\s+SET\b|INSERT\s+INTO\b)[^\n;]*",
                             content, re.IGNORECASE | re.MULTILINE):
        findings[("Embedded data backfill (UPDATE/INSERT in migration)", " ".join(match.group(0).split()))] += 1

    return findings


def read_file(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeError):
        return None


def introduced_findings(tool_name, tool_input, path):
    is_sql = path.lower().endswith(".sql")
    if tool_name == "Write":
        return scan(text(tool_input, "content"), is_sql)

    old, new = text(tool_input, "old_string"), text(tool_input, "new_string")
    before = read_file(path)
    if before is None or not old or old not in before:
        return scan(new, is_sql)
    after = before.replace(old, new) if tool_input.get("replace_all") is True else before.replace(old, new, 1)
    return scan(after, is_sql) - scan(before, is_sql)


def main():
    payload = read_payload()
    if payload is None:
        return 0
    tool_name, tool_input, _cwd = payload
    path = tool_input["file_path"]
    if not is_migration_path(path):
        return 0

    found = {rule for rule, _ in introduced_findings(tool_name, tool_input, path)}
    if not found:
        return 0

    lines = ["[backend-design] migration-safety review for {}".format(path)]
    for rule, why in WHY.items():
        if rule in found:
            lines.append("- {}: {}".format(rule, why))
    lines.append("See the migration-safety skill. Run /backend-design:review-migration for a full review.")
    warn(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
