# Plugin install counts

Plugin authors listed on HOL can see how many Guard users have their plugin installed. Guard sends these counts only after you turn them on, and it sends nothing about you or your machine.

```bash
hol-guard telemetry plugins on                  # start weekly counts
hol-guard telemetry plugins send --dry-run      # print what would be sent, without sending
hol-guard telemetry plugins status
hol-guard telemetry plugins off                 # stop and delete the device key
```

## What is sent

Once a week, the Guard daemon downloads the public HOL listing index and the native runtime matches the plugins installed under `~/.claude` (or `$CLAUDE_CONFIG_DIR`), `~/.codex` (or `$CODEX_HOME`), `~/.gemini` and `~/.cursor` against it on your machine. A plugin is matched only by the repository in its manifest. The report lists, for each matched plugin:

| Field | Example |
|---|---|
| `slug` | the public HOL listing |
| `runtime` | `claude-code`, `codex`, `gemini` or `cursor` |
| `version` | the installed plugin version |
| `key` | `HMAC-SHA256(device key, "<week>:<slug>:<runtime>")` |

The report also carries the ISO week and the Guard version. Nothing else is sent: no user, machine, path, hostname or workspace identifier. Plugins that are not public HOL listings are never included.

The device key is 32 random bytes stored in the Guard home with owner-only permissions, and it never leaves the machine. Because the key is mixed with the week, listing and runtime, HOL can count distinct installs of a listing in a week but cannot link one machine's listings together or follow a machine from one week to the next. `off` deletes the key, so turning counts on again starts an unrelated series.

HOL does not store the sender's IP address with a report, keeps reports for 13 weeks, and never shows a count below 10 installs.

## When reports are sent

The daemon checks every six hours and sends at most one report per ISO week, only while counts are on. `send` sends this week's report immediately; `send --dry-run` builds the report, with a throwaway key if counts are off, and prints it.
