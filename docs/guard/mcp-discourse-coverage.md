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
- `discourse_create_private_message`
- `discourse_reply_private_message`
- `discourse_invite_to_private_message`

All other names **inherit** existing Guard policy. The contribution does
not claim an exhaustive inventory of Discourse's expanding toolsets, and
does not claim to prevent every write or bypass of Discourse's own
authorization. Discourse MCP registers write tools only when `--allow_writes` is supplied.
Invoking a registered write tool additionally requires a matching credential
for the selected site; without one, the server returns an error.

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
