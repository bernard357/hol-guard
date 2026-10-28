"""Narrow, off-by-default policy assertions for the opt-in Discourse MCP contribution."""

from __future__ import annotations

import json
from pathlib import Path

from .mcp_contribution_loader import validate_mcp_contribution_file

from .mcp_contribution_client import mcp_tool_state

_CONTRIBUTION = (
    Path(__file__).resolve().parents[1]
    / "contributions/mcp-servers/mcp.discourse.json"
)
_TRUST_BINDING = (
    Path(__file__).resolve().parents[1]
    / "contracts/extensions/trust/command.mcp-discourse.v1.json"
)


def _payload() -> dict[str, object]:
    return validate_mcp_contribution_file(_CONTRIBUTION)


def test_discourse_launch_identity_and_opt_in_trust() -> None:
    contribution = _payload()
    assert contribution["id"] == "mcp.discourse"
    assert contribution["trustClass"] == "external"
    assert contribution["activation"] == "opt-in"
    assert contribution["publisher"] == {
        "id": "community.kantorcodes",
        "displayName": "Michael Kantor",
        "url": "https://github.com/kantorcodes",
    }
    trust = json.loads(_TRUST_BINDING.read_text(encoding="utf-8"))
    assert trust == {
        "schemaVersion": "guard.extension-trust-binding.v1",
        "extension": "command.mcp-discourse",
        "trustClass": "external",
    }
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
        "discourse_perform_reviewable_action",
        "discourse_create_private_message",
        "discourse_reply_private_message",
        "discourse_invite_to_private_message",
    }
    declared = {tool["name"]: tool["state"] for tool in contribution["tools"]}
    # This is an intentionally narrow opt-in profile: adding another named tool
    # must be an explicit reviewed scope change, not an accidental allow rule.
    assert set(declared) == required | {"other"}
    assert declared["other"] == "inherit"
    assert all(state != "allow" for state in declared.values())
    for name in required:
        assert declared[name] == "review"
        assert mcp_tool_state(contribution, name) == "review"


def test_discourse_unlisted_tools_preserve_host_policy() -> None:
    contribution = _payload()
    assert mcp_tool_state(contribution, "discourse_read_topic") == "inherit"
    assert mcp_tool_state(contribution, "discourse_unlisted_future_tool") == "inherit"
