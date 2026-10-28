# Discourse MCP: narrow Guard coverage

This is an **external, locally opt-in** HOL Guard contribution for
[Discourse MCP](https://github.com/discourse/discourse-mcp). It is separate from
the Discourse MCP distribution; Discourse does not bundle or maintain HOL Guard.

## Installation identity

Discourse's published package currently uses Node.js 24 or later and:

```sh
npx -y @discourse/mcp@latest
```

The Guard contribution matches the `npx` package identity
`@discourse/mcp` rather than assuming the configured MCP server name
authenticates the installed code. It only takes effect when the local
administrator enables the external contribution.

## Selected review boundary

The initial scoped policy requests review of these exact MCP tool names:

- `discourse_create_post`
- `discourse_create_topic`
- `discourse_update_topic`
- `discourse_perform_reviewable_action`
- `discourse_create_private_message`
- `discourse_reply_private_message`
- `discourse_invite_to_private_message`

The moderation action is registered only when Discourse MCP write tools and its opt-in moderation toolset are enabled; a selected reviewable action can approve, reject or otherwise change forum content. Guard review is still required before the selected action is submitted.

All other names **inherit** existing Guard policy. The contribution does
not claim an exhaustive inventory of Discourse's expanding toolsets, and
does not claim to prevent every write or bypass of Discourse's own
authorization. Discourse MCP registers **built-in** write tools when
`--allow_writes` is passed, or when `"allow_writes": true` is set in a
`--profile` JSON file without an overriding CLI flag. Invoking one of
these registered tools additionally requires matching credentials for the
selected Discourse site; without them, the server returns an error.

Separately, whether the operator passes `--site` at startup or selects a site
later with `discourse_select_site`, the default `--tools_mode auto` may discover
remote Tool Execution API tools (`remote_*`). Remote tool calls do
**not** check `allow_writes` in the MCP server and can have side effects. To
disable remote discovery, select `--tools_mode discourse_api_only` (or set
`"tools_mode": "discourse_api_only"` in the profile). This Guard contribution
only enumerates the seven named built-in write tools above; it does not claim
coverage of dynamically discovered remote tools.

Before allowing a call, confirm the selected Discourse site, target,
intended audience (especially for private messages), and content.
Normal Guard floors, stronger blocks, and local custom grants remain
authoritative. This contribution cannot itself authorize a tool call.

## Validation

The source file is `contributions/mcp-servers/mcp.discourse.json`;
the matching trust binding is
`contracts/extensions/trust/command.mcp-discourse.v1.json`.
The focused payload assertions live in
`tests/test_guard_mcp_discourse_contribution.py`.

To validate in a fully installed HOL Guard repository:

```sh
python scripts/refresh_extension_artifacts.py --check-trust
uv run --no-sync pytest tests/test_guard_mcp_discourse_contribution.py tests/test_guard_mcp_server_contribution.py --tb=short
```

This change was authored with AI assistance for independent review.
No end-to-end package install, local Guard tests, Discourse API calls,
release publication, or external developer adoption are asserted.
