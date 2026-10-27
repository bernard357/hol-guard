# Countly MCP: opt-in application mutation review

This is a HOL-authored, **external and locally opt-in** HOL Guard contribution
for [Countly MCP](https://github.com/Countly/countly-mcp-server). It does not
modify, ship inside, or imply endorsement by Countly or its maintainers.
Countly maintains its MCP server; HOL is responsible for the Guard policy proposal.

## Source identity and setup

The official Countly MCP server currently publishes npm package
`countly-mcp-server` (source `package.json` version 1.7.0, checked October 27, 2026).
Its README documents Node.js 18+ and a stdio launcher:

```sh
COUNTLY_SERVER_URL=https://your-countly-instance.com \
COUNTLY_AUTH_TOKEN=your-token \
npx -y countly-mcp-server
```

These values are illustrations only. Do not copy credentials into commits or
logs. The Guard contribution matches the package identity, not an arbitrary
configured MCP server name. It remains inert until a local administrator enables
this external policy.

## Narrow review boundary

The contribution requests review of only these Countly source-authored MCP tools:

- `apps_create`: create a Countly application
- `apps_delete`: delete a Countly application
- `apps_reset`: reset application data
- `apps_delete_user`: remove an application user

All other tools **inherit** existing Guard policy. This is intentionally not
a complete review of Countly's broader application, analytics, dashboards or
user-management mutation APIs. New or renamed tools are not automatically covered.

Countly MCP supports per-tool credentials, user permissions and edition-aware
tool listing. Those Countly-side controls still apply. A Guard review decision
cannot grant Countly API privileges or make a request safe. Verify the Countly
instance, app ID, user or dataset, actual operation and credential scope before
approving. Keep read-only workflows on read-only credentials where possible.
Existing stronger Guard floors, blocks and device-local grants remain authoritative.

## Files and validation

- Canonical source: `contributions/mcp-servers/mcp.countly.json`
- External trust binding: `contracts/extensions/trust/command.mcp-countly.v1.json`
- Focused tests: `tests/test_guard_mcp_countly_contribution.py`

To validate with a complete local HOL Guard checkout:

```sh
python scripts/refresh_extension_artifacts.py --check-trust
uv run --no-sync pytest tests/test_guard_mcp_countly_contribution.py tests/test_guard_mcp_server_contribution.py --tb=short
```

This is an AI-assisted HOL contribution proposed for independent technical,
security and maintainer review. No local native build, installed Guard hook test,
Countly API write, official acceptance, release or nonauthor adoption is claimed.
