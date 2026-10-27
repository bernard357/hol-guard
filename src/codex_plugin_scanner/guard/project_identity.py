"""Portable project identity for cross-device Guard decision memory.

Project-scoped memory must not depend on where a repository is cloned on one
machine. The resident derives an opaque classification from the workspace's
Git metadata, keeping local filesystem paths out of the identity itself; this
module asks it and keeps only the metadata glue. Repository-controlled
metadata is not an authentication boundary; callers must never use the
identity alone to grant permissive authority.
"""

from __future__ import annotations

import functools
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PORTABLE_PROJECT_IDENTITY_PREFIX = "git-project:v1:"
_MAX_REQUEST_BYTES = 64 * 1024


class ProjectIdentityError(RuntimeError):
    """The resident gave no usable project identity answer."""


def is_portable_project_identity(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(PORTABLE_PROJECT_IDENTITY_PREFIX)
        and len(value) == len(PORTABLE_PROJECT_IDENTITY_PREFIX) + 64
        and all(character in "0123456789abcdef" for character in value[-64:])
    )


def resolve_portable_project_identity(workspace: str | Path | None) -> str | None:
    """Return a stable opaque classification for a conventional Git project.

    The identity is stable across clone locations when the clones share the
    same canonical origin remote and the initial HEAD reflog records that
    origin. Both files are repository-controlled and therefore do not
    authenticate the workspace. The resident reads them directly and never
    launches a subprocess. A workspace the resident cannot settle, or no
    resident at all, has no identity: that only narrows what portable memory
    matches.
    """
    if isinstance(workspace, Path):
        workspace = str(workspace)
    if not isinstance(workspace, str) or not workspace.strip():
        return None
    from .native_execution import _resident_request
    from .native_resident_decision import ResidentOperation, resident_decide

    operation = ResidentOperation(
        operation="project_identity",
        feature="project-identity-v1",
        prefix="native_project_identity",
        request_schema="guard-project-identity-request.v1",
        result_schema="guard-project-identity-result.v1",
        request_id_prefix="project-identity",
        timeout_seconds=2.0,
        error=ProjectIdentityError,
    )

    def validate(payload: dict[str, Any]) -> None:
        identity = payload.get("identity", False)
        if set(payload) != {"kind", "identity"} or not (identity is None or is_portable_project_identity(identity)):
            raise ProjectIdentityError(operation.invalid)

    try:
        payload = resident_decide(
            operation,
            functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
            {"kind": "resolve", "workspace": workspace},
            None,
            validate,
        )
    except ProjectIdentityError:
        return None
    return payload["identity"]


def resolve_project_identity_from_metadata(metadata: Mapping[str, object]) -> str | None:
    """Resolve explicit project identity first, upgrading path-like ids when possible."""
    explicit = _first_string(metadata, "project_id", "projectId")
    if explicit and not _looks_like_local_path(explicit):
        return explicit

    workspace = _first_string(metadata, "workspace_path", "workspacePath") or explicit
    portable = resolve_portable_project_identity(workspace)
    if portable is not None:
        return portable
    return explicit


def enrich_project_identity_metadata(metadata: Mapping[str, object]) -> dict[str, object]:
    """Return metadata with the canonical project identity in ``project_id``."""
    enriched = {str(key): value for key, value in metadata.items()}
    project_identity = resolve_project_identity_from_metadata(metadata)
    if project_identity is not None:
        enriched["project_id"] = project_identity
    return enriched


def _first_string(metadata: Mapping[str, object], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _looks_like_local_path(value: str) -> bool:
    normalized = value.strip()
    if normalized.startswith(("/", "~/", "./", "../", "\\\\")):
        return True
    return len(normalized) >= 3 and normalized[1:3] in {":\\", ":/"}
