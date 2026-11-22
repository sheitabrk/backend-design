"""
Shared input/output for the backend-design PreToolUse hooks.

Input: Claude Code sends the hook event as JSON on stdin. Anything that is not
the expected shape (invalid JSON, a list, a non-object tool_input) is ignored,
so a hook never crashes on input it did not expect.

Output: Claude Code does not pass stderr from a hook that exits 0 to Claude.
Warnings therefore go to stdout as `hookSpecificOutput.additionalContext`, the
documented way for a PreToolUse hook to add context without allowing, denying
or asking. No permissionDecision is set, so the write proceeds as normal.
"""

import json
import sys


def read_write_or_edit():
    """Return (tool_name, tool_input) for a Write/Edit event, or None."""
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    tool_name = payload.get("tool_name")
    if tool_name not in ("Write", "Edit"):
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    return tool_name, tool_input


def text_field(tool_input, key):
    """A string field from tool_input, or "" when missing or not a string."""
    value = tool_input.get(key)
    return value if isinstance(value, str) else ""


def emit_warning(lines):
    """Send advisory text to Claude. Never blocks the tool call."""
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "\n".join(lines),
        }
    }
    sys.stdout.write(json.dumps(out))
    sys.stdout.write("\n")
