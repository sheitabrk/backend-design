"""Shared input and output handling for the PreToolUse hooks."""

import json
import sys


def read_payload():
    """Return (tool_name, tool_input, cwd), or None if there is nothing to check."""
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if tool_name not in ("Write", "Edit") or not isinstance(tool_input, dict):
        return None
    if not text(tool_input, "file_path"):
        return None
    return tool_name, tool_input, text(payload, "cwd")


def text(mapping, key):
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def relative_path(path, cwd):
    """Lower-cased forward-slash path, relative to the project when inside it."""
    p = path.replace("\\", "/").lower()
    base = cwd.replace("\\", "/").lower().rstrip("/")
    if base and p.startswith(base + "/"):
        return p[len(base) + 1:]
    return p


def warn(lines):
    """Hand the warning to Claude. No permissionDecision: never approve or block."""
    json.dump(
        {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "\n".join(lines)}},
        sys.stdout,
    )
