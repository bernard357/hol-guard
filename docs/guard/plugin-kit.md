# HOL Guard Plugin Kit

`hol-guard plugin` turns one plugin source into a package for every agent runtime that can load it, and tells you what a marketplace or runtime loader would reject before you publish.

The Kit runs inside the HOL Guard native runtime. It reads only the folder you name, never follows symlinks, runs no commands and makes no network calls. Nothing is uploaded.

## Commands

| Command | What it does | Exit code |
| :--- | :--- | :--- |
| `hol-guard plugin check [path] [--strict]` | Detects the plugin, lists its skills, MCP servers, commands and agents, and reports problems. `--strict` fails on warnings too. | 0 passed, 1 failed, 2 could not run |
| `hol-guard plugin package [path] [--out DIR] [--runtimes a,b] [--force] [--strict]` | Runs `check`, then writes one folder per runtime. Writes nothing when the check fails. Refuses a non-empty output folder unless `--force`. | 0 packaged, 1 check failed, 2 could not run |
| `hol-guard plugin links [path]` | Prints the install command for each runtime the repository already supports, and what is left to list it everywhere. | 0, or 2 could not run |
| `hol-guard plugin init [path] [--name NAME]` | In a plugin repository, writes `hol.json`. In an empty folder with `--name`, scaffolds a minimal Claude Code plugin with one skill. Never overwrites a file. | 0, or 2 could not run |

Every command accepts `--json` for the full machine-readable result.

## Sources the Kit reads

| Source | File |
| :--- | :--- |
| Claude Code plugin | `.claude-plugin/plugin.json`, with `.mcp.json`, `skills/`, `commands/`, `agents/` and `hooks/hooks.json` |
| Claude Code marketplace | `.claude-plugin/marketplace.json` |
| Codex plugin | `.codex-plugin/plugin.json` |
| Codex marketplace | `.agents/plugins/marketplace.json` |
| Gemini CLI extension | `gemini-extension.json`, with its context file (`GEMINI.md` by default) |
| MCP Registry server | `server.json` (npm, PyPI and OCI packages, or a remote) |
| Agent skills | any `SKILL.md` with `name` and `description` frontmatter |

When several manifests describe the same plugin, the shallowest one wins and the others fill in missing fields. The repository comes from the manifest, then `package.json`, then the `origin` remote in `.git/config`.

## Runtimes the Kit writes

| Runtime | Output | Carries |
| :--- | :--- | :--- |
| `claude-code` | `.claude-plugin/plugin.json`, `.mcp.json` | skills, MCP servers, commands, agents, hooks |
| `codex` | `.codex-plugin/plugin.json`, `.mcp.json` | skills, MCP servers |
| `gemini-cli` | `gemini-extension.json` | MCP servers, context file |
| `cursor` | `.cursor/mcp.json` | MCP servers |
| `vscode` | `.vscode/mcp.json` | MCP servers |
| `opencode` | `opencode.json` | MCP servers |
| `mcp-registry` | `server.json` | the repository's own `server.json`, or one generated for a single remote MCP server on GitHub |
| `agent-skills` | `skills/<name>/` | skills |

`check` lists, for each runtime, whether it is supported and which components it drops. MCP environment variables are written as references in each runtime's own syntax (`${NAME}`, `$NAME`, `${env:NAME}` or `{env:NAME}`). The Kit never copies a variable's value; `check` warns when a config ships a literal value for a variable whose name looks secret.

`package` also writes `hol.provenance.json`: the generator version, the plugin name and version, a SHA-256 digest of the source files it read, and the digest of every file it wrote. It has no timestamps, so the same source always produces the same package.

## hol.json

`hol-guard plugin init` writes a `hol.json` that `package` reads when no flags are given:

```json
{
  "schema": "hol.plugin-kit.config.v1",
  "out": "dist/hol-plugin",
  "runtimes": ["claude-code", "codex", "cursor"]
}
```

`out` is relative to the repository and cannot leave it. The Kit skips `dist/` and any folder holding `hol.provenance.json`, so a package is never read back as source.

## List the plugin

`hol-guard plugin links` prints the install commands that work today and the steps still open, such as adding a Codex marketplace file or publishing to the MCP Registry. For a GitHub repository it also prints the HOL link that verifies ownership and claims the plugin's listing on HOL.

HOL links carry `utm_source=hol-guard` campaign parameters, so HOL can count visits that came from the Kit. The Kit itself sends nothing.

After the first successful `check` or `package` in text mode, the Kit prints a one-line tip showing how to turn on Guard for the agents you test with. It prints once per Guard home and never in `--json` output, and it only prints a command.
