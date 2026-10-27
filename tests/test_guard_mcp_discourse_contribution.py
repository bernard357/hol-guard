"""Narrow, off-by-default policy assertions for the opt-in Discourse MCP contribution."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.mcp_server_contribution import validate_mcp_contribution

from .mcp_contribution_client import mcp_tool_state

_CONTRIBUTION = (
    Path(__file__).resolve().parents[1]
    / "contributions/mcp-servers/mcp.discourse.json"
)


def _payload() -> dict[str, object]:
    result = json.loads(_CONTRIBUTION.read_text(encoding="utf-8"))
    assert isinstance(result, dict)
    validate_mcp_contribution(result, filename=_CONTRIBUTION.name)
    return result


def test_discourse_launch_identity_and_opt_in_trust() -> None:
    contribution = _payload()
    assert contribution["id"] == "mcp.discourse"
    assert contribution["trustClass"] == "external"
    assert contribution["activation"] == "opt-in"
    assert contribution["launch"] == {
        "kind": "package-launcher",
        "command": "npx",
        "package": "@discourse/mcp",
    }


def test_discourse_selected_write_actions_require_review() -> None:
    contribution = _payload()
    required = {
        "discourse_create_post",
        "discourse_create_topic",
        "discourse_update_topic",
        "discourse_create_private_message",
    }
    declared = {tool["name"]: tool["state"] for tool in contribution["tools"]}
    assert required <= declared.keys()
    for name in required:
        assert declared[name] == "review"
        assert mcp_tool_state(contribution, name) == "review"


def test_discourse_unlisted_tools_preserve_host_policy() -> None:
    contribution = _payload()
    assert mcp_tool_state(contribution, "discourse_read_topic") == "inherit"
    assert mcp_tool_state(contribution, "discourse_unlisted_future_tool") == "inherit"
