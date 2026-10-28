"""Focused source-contract tests for HOL's opt-in Countly MCP contribution."""

from __future__ import annotations

import json
from pathlib import Path

from .mcp_contribution_client import mcp_tool_state
from .mcp_contribution_loader import validate_mcp_contribution_file

_ROOT = Path(__file__).resolve().parents[1]
_CONTRIBUTION = _ROOT / "contributions/mcp-servers/mcp.countly.json"
_TRUST_BINDING = _ROOT / "contracts/extensions/trust/command.mcp-countly.v1.json"

_REVIEW_TOOLS = frozenset(
    {"apps_create", "apps_delete", "apps_reset", "apps_delete_user"}
)


def _payload() -> dict[str, object]:
    """Read and validate Countly's reviewed input rather than generated projections."""
    return validate_mcp_contribution_file(_CONTRIBUTION)


def test_countly_package_identity_is_external_and_opt_in() -> None:
    """Ensure a configured server alias cannot authorize this optional policy."""
    contribution = _payload()
    assert contribution["id"] == "mcp.countly"
    assert contribution["activation"] == "opt-in"
    assert contribution["trustClass"] == "external"
    assert contribution["publisher"] == {
        "id": "community.kantorcodes",
        "displayName": "Michael Kantor (HOL)",
        "url": "https://github.com/kantorcodes",
    }
    assert contribution["launch"] == {
        "kind": "package-launcher",
        "command": "npx",
        "package": "countly-mcp-server",
    }
    trust = json.loads(_TRUST_BINDING.read_text(encoding="utf-8"))
    assert trust == {
        "schemaVersion": "guard.extension-trust-binding.v1",
        "extension": "command.mcp-countly",
        "trustClass": "external",
    }


def test_countly_exact_application_mutations_require_review() -> None:
    """Require approval on the four Countly APIs scoped in the author proposal."""
    contribution = _payload()
    declared = {tool["name"]: tool["state"] for tool in contribution["tools"]}
    assert set(declared) == (_REVIEW_TOOLS | {"other"})
    for name in _REVIEW_TOOLS:
        assert declared[name] == "review"
        assert mcp_tool_state(contribution, name) == "review"


def test_countly_unlisted_tools_keep_existing_guard_policy() -> None:
    """Avoid implying coverage of all of Countly's many other MCP writes."""
    contribution = _payload()
    assert mcp_tool_state(contribution, "apps_list") == "inherit"
    assert mcp_tool_state(contribution, "apps_update") == "inherit"
    assert mcp_tool_state(contribution, "future_countly_tool") == "inherit"
    assert all(tool["state"] != "allow" for tool in contribution["tools"])

def test_countly_similarly_named_tools_do_not_expand_review_scope() -> None:
    """Only the four declared application mutations acquire Countly review."""
    contribution = _payload()
    for name in (
        "apps_delete_user_batch",
        "apps_delete_all",
        "apps_reset_preview",
        "apps_create_template",
        "other_apps_delete",
    ):
        assert mcp_tool_state(contribution, name) == "inherit"
