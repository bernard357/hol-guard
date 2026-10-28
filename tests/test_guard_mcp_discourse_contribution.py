"""Narrow, off-by-default policy assertions for the opt-in Discourse MCP contribution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity

from .mcp_contribution_loader import validate_mcp_contribution_file
from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .mcp_extension_driver import apply_contributed_mcp_decision
from .test_guard_mcp_server_grants import _artifact, _AuthorityStore, _layer

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


_REVIEW_TOOLS = frozenset({
    "discourse_create_post",
    "discourse_create_topic",
    "discourse_update_topic",
    "discourse_perform_reviewable_action",
    "discourse_create_private_message",
    "discourse_reply_private_message",
    "discourse_invite_to_private_message",
})

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
    required = _REVIEW_TOOLS
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

@pytest.mark.parametrize("tool_name", sorted(_REVIEW_TOOLS))
def test_discourse_native_selected_write_needs_opt_in_review(tool_name: str) -> None:
    """Exercise the actual native MCP decision, not only the Python source map."""
    identity = build_mcp_server_identity(
        config_path="", command="npx", args=("-y", "@discourse/mcp"), transport="stdio"
    )
    artifact = _artifact(identity, tool_name)
    assert apply_contributed_mcp_decision(_AuthorityStore(), artifact, "allow") is None

    enabled = _AuthorityStore(
        (_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-discourse", ControlState.ENABLED),)
    )
    decision = apply_contributed_mcp_decision(enabled, artifact, "allow")
    assert decision is not None
    assert decision[:2] == ("review", "catalog-mcp-extension")


@pytest.mark.parametrize("tool_name", ["discourse_read_topic", "discourse_unlisted_future_tool"])
def test_discourse_native_unlisted_tool_inherits_host_policy(tool_name: str) -> None:
    """Enabling this narrow policy must not intercept read and future tools."""
    identity = build_mcp_server_identity(
        config_path="", command="npx", args=("-y", "@discourse/mcp"), transport="stdio"
    )
    artifact = _artifact(identity, tool_name)
    enabled = _AuthorityStore(
        (_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-discourse", ControlState.ENABLED),)
    )
    assert apply_contributed_mcp_decision(enabled, artifact, "allow") is None
