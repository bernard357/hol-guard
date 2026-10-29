"""A plugin manifest the agent edits in a checkout of its own project under ``/tmp``.

A repository that ships an agent plugin keeps its manifest in a hidden
``.claude-plugin`` or ``.codex-plugin`` directory. Agents add a worktree of the
project straight in ``/tmp``, outside the home directory, and edit the manifest
there with the harness's own read and edit tools. The manifest is committed so
the worktree the agent adds holds it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

PLUGIN_MANIFEST_CASE = "omp-native-edit-tmp-worktree-plugin-manifest"
PLUGIN_MANIFEST = "integrations/app/.claude-plugin/plugin.json"
PLUGIN_MANIFEST_TEXT = '{\n  "name": "app",\n  "author": "Example"\n}\n'


def stage_plugin_manifest(workspace: Path, home: Path | None, scenario_id: str) -> None:
    """Commit the manifest to the branch the agent works on."""
    if scenario_id != PLUGIN_MANIFEST_CASE or home is None:
        return
    target = workspace / PLUGIN_MANIFEST
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(PLUGIN_MANIFEST_TEXT, encoding="utf-8", newline="\n")
    environment = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "WINDIR") if k in os.environ}
    environment.update(HOME=str(home), USERPROFILE=str(home), GIT_CONFIG_NOSYSTEM="1")
    for args in (
        ("add", "--", PLUGIN_MANIFEST),
        ("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add plugin manifest"),
    ):
        subprocess.run(
            ["git", "-C", str(workspace), *args], env=environment, check=True, capture_output=True, timeout=15
        )
