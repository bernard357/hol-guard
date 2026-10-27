"""GuardStore compatibility layer for portable project-scoped memory."""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from .action_lattice import guard_action_severity
from .project_identity import (
    ProjectIdentityError,
    enrich_project_identity_metadata,
    is_portable_project_identity,
    resolve_portable_project_identity,
)
from .store_base import PolicyDecisionLookupResult
from .store_policy import _DEGRADED_AUTHORITY_REVISION
from .store_policy import POLICY_DECISION_LOOKUP_FEATURE as _LOOKUP
from .store_policy import POLICY_LOOKUP_MEMORY_FEATURE as _MEMORY
from .store_policy import PORTABLE_COMPOSITION_LOOKUP_FEATURE as _PORTABLE_COMPOSITION
from .store_policy import RUNTIME_SAVED_REUSE_FEATURE as _SAVED_REUSE

# A decision at or above this rank can only hold a caller back, so a lookup
# that lost its portable half may still return it.
_REVIEW_FLOOR = guard_action_severity("review")


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _restrictive_only(decision: object) -> dict[str, object] | None:
    """A decision as a lookup whose portable half went unread may still use it.

    This mirrors the resident's own fallback for a portable half it cannot
    claim (``policy_lookup_portable``). A decision below the review floor
    grants a permission the unread half might have withheld, so it is
    dropped. One at or above the floor can only hold the caller back, so it
    survives, without the preview-only authority revision that would present
    it as a claim.
    """
    if not isinstance(decision, dict):
        return None
    if guard_action_severity(decision.get("action")) < _REVIEW_FLOOR:
        return None
    return {key: value for key, value in decision.items() if key != "_approval_authority_revision"}


def _restrictive_only_lookup(lookup: Any) -> Any:
    """The same, over a whole lookup result."""
    if not isinstance(lookup, Mapping):
        return lookup
    return {**lookup, "decision": _restrictive_only(lookup.get("decision"))}


# Store mixins are composed dynamically in ``GuardStore``. Sibling mixins use
# the same file-level pyright setting because ``super()`` members are supplied
# by the final MRO rather than a direct base class.
class StorePortableProjectMemoryMixin:
    """Add restrictive portable Git project policy without weakening local scope."""

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
        operation = super().get_guard_operation_for_approval_request(request_id)
        if not isinstance(operation, dict):
            return operation
        metadata = operation.get("metadata")
        if not isinstance(metadata, Mapping):
            return operation
        return {
            **operation,
            "metadata": enrich_project_identity_metadata(metadata, guard_home=self.guard_home),
        }

    def peek_saved_decision_groups(
        self,
        harness: str,
        probes: Sequence[tuple[str, str | None]],
        *,
        workspace: str | None,
        publisher: str | None,
        runtime_exact_match_context: str | None,
        memory_command: str | None,
        memory_artifact_type: str | None,
        memory_artifact_name: str | None,
        current_action: str,
        approval_context_inputs: Mapping[str, object],
    ) -> dict[str, Any] | None:
        """Peek saved decisions for several ``(artifact_id, artifact_hash)`` probes in one resident call.

        The resident expands each probe's direct id with its exact-command and
        memory ids and composes them most restrictive (with the portable Git
        workspace); across probes a strictly more severe decision wins. Nothing is consumed. The first probe names
        the current action: the resident also checks a saved allow's context
        token against its hash, explains a miss, and composes the reuse verdict
        for ``current_action``. Returns ``decision``, ``ignored_local_integrity``,
        ``reuse`` (the verdict payload), ``saved_present`` and
        ``saved_artifact_hash``. ``None`` means the home serves no saved
        authority, so there is no saved decision to compose.
        """
        evidence = self.policy_lookup_evidence()
        if evidence.degraded_trust_status is not None:
            return None
        reuse = {"current_action": current_action, "approval_context_inputs": dict(approval_context_inputs)}
        memory = (memory_command, memory_artifact_type, memory_artifact_name)
        return self._send_memory_probe_groups(
            evidence, harness, probes, workspace, publisher, runtime_exact_match_context, memory, reuse
        )

    def resolve_policy_decision_lookup_with_memory_pattern(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        *,
        memory_command: str | None = None,
        memory_artifact_type: str | None = None,
        memory_artifact_name: str | None = None,
        consume_one_shot: bool = True,
    ) -> PolicyDecisionLookupResult:
        """Peek the direct, exact-command and memory candidates in one resident call.

        The resident composes them most restrictive with the portable Git
        workspace, as the consuming path below does one probe at a time.
        """
        if consume_one_shot or not artifact_id or not artifact_hash:
            return super().resolve_policy_decision_lookup_with_memory_pattern(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                memory_command=memory_command,
                memory_artifact_type=memory_artifact_type,
                memory_artifact_name=memory_artifact_name,
                consume_one_shot=consume_one_shot,
            )
        evidence = self.policy_lookup_evidence(now=now)
        if evidence.degraded_trust_status is not None:
            return {
                "decision": None,
                "ignored_local_integrity": None,
                "trust_status": evidence.degraded_trust_status,
                "authority_revision": _DEGRADED_AUTHORITY_REVISION,
            }
        memory = (memory_command, memory_artifact_type, memory_artifact_name)
        return self._send_memory_probe_groups(
            evidence, harness, [(artifact_id, artifact_hash)], workspace, publisher, runtime_exact_match_context, memory
        )

    def _send_memory_probe_groups(
        self,
        evidence: Any,
        harness: str,
        probes: Sequence[tuple[str, str | None]],
        workspace: str | None,
        publisher: str | None,
        runtime_exact_match_context: str | None,
        memory: tuple[str | None, str | None, str | None],
        reuse: Mapping[str, object] | None = None,
    ) -> Any:
        """Send direct-id probe groups for the resident to expand and compose.

        Without ``reuse`` the request names one probe and answers its full
        ``lookup_result``.
        """
        request = self.policy_decision_lookup_request(
            evidence,
            harness=harness,
            artifact_id=probes[0][0],
            artifact_hash=None,
            workspace=workspace,
            publisher=publisher,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=False,
        )
        command, artifact_type, artifact_name = memory
        portable, unread = self._portable_probe_workspace(workspace)
        request["probe_groups"] = {
            "portable_workspace": portable,
            "groups": [{"artifact_hash": h, "candidate_artifact_ids": [i]} for i, h in probes],
            **({"reuse": reuse} if reuse is not None else {}),
            "memory": {
                "command": command,
                "artifact_type": artifact_type,
                "artifact_name": artifact_name,
                "harness": harness,
            },
        }
        # Gated on the expansion capability, not the lookup's: the groups above
        # carry only their direct id, so a runtime that does not expand them
        # would answer a narrower question than was asked, and the
        # probe-groups contract would reject the ``memory`` field anyway. The
        # named missing capability says that; a serde error would not.
        lookup = self.send_policy_decision_lookup(request, required_feature=_MEMORY)
        return _restrictive_only_lookup(lookup) if unread else lookup

    def resolve_runtime_saved_decision(
        self,
        current: Mapping[str, object],
        legacy: Mapping[str, object],
        alias: Mapping[str, object] | None,
        reuse: Mapping[str, object] | None = None,
    ) -> tuple[PolicyDecisionLookupResult, dict[str, Any] | None, dict[str, Any] | None]:
        """Resolve a runtime hook evaluation's saved decision in one resident call.

        ``current`` and ``legacy`` probe the request hash and the legacy content
        hash with their exact-command and memory candidates; ``alias`` probes
        the Claude alias of a legacy ``claude-code:`` artifact when neither
        matched. Nothing is consumed. Returns the trust and integrity evidence,
        the decision this artifact may use and, with ``reuse``, the resident's
        ``saved_reuse`` (a degraded store builds only its query).
        """
        evidence = self.policy_lookup_evidence()
        if evidence.degraded_trust_status is not None:
            degraded: PolicyDecisionLookupResult = {
                "decision": None,
                "ignored_local_integrity": None,
                "trust_status": evidence.degraded_trust_status,
                "authority_revision": _DEGRADED_AUTHORITY_REVISION,
            }
            query = None if reuse is None else {"query": self._degraded_saved_reuse_query(current, reuse)}
            return degraded, None, query
        probes = {"current": current, "legacy": legacy, **({"alias": alias} if alias is not None else {})}
        resolved = {
            name: self._portable_probe_workspace(_text(probe.get("workspace"))) for name, probe in probes.items()
        }
        unread = any(probe_unread for _, probe_unread in resolved.values())
        runtime = {name: {**probe, "portable_workspace": resolved[name][0]} for name, probe in probes.items()}
        request = self.policy_decision_lookup_request(
            evidence,
            harness=str(current["harness"]),
            artifact_id=_text(current.get("artifact_id")),
            artifact_hash=_text(current.get("artifact_hash")),
            workspace=_text(current.get("workspace")),
            publisher=_text(current.get("publisher")),
            runtime_exact_match_context=_text(current.get("exact_match_context")),
            consume_one_shot=False,
        )
        request["probe_groups"] = {"groups": [], "runtime": {**runtime, **({"reuse": reuse} if reuse else {})}}
        payload = self.send_policy_decision_lookup(request, required_feature=_SAVED_REUSE if reuse else _LOOKUP)
        saved_reuse = None if reuse is None else payload.get("saved_reuse")
        if unread:
            # A probe sent without its identity read only local authority, so
            # neither its decision nor a reuse built on it may grant anything.
            return _restrictive_only_lookup(payload["lookup"]), _restrictive_only(payload["decision"]), None
        return payload["lookup"], payload["decision"], saved_reuse

    def _degraded_saved_reuse_query(self, current: Mapping[str, object], reuse: Mapping[str, object]) -> dict[str, Any]:
        """The ``saved_reuse`` query of a store that serves no saved decision."""
        from .runtime.approval_context import approval_context_tokens_validation_reason as validate

        token, keys = reuse.get("cursor_native_token"), ("artifact_id", "artifact_hash", "workspace", "publisher")
        reason, stored_hash = (
            self.approval_reuse_diagnostic(str(current["harness"]), *(_text(current.get(key)) for key in keys))
            if token is None
            else (None, None)
        )
        return {
            "current_action": reuse["current_action"],
            **dict.fromkeys(("stored_action", "stored_artifact_hash", "stored_validation_reason"), None),
            **dict.fromkeys(("stored_present", "integrity_failure"), False),
            "cursor_native_present": token is not None,
            "cursor_validation_reason": None if token is None else validate(token, current["artifact_hash"]),
            "diagnostic_reason": reason,
            "diagnostic_stored_hash": stored_hash,
        }

    def mcp_policy_lookup_input(self, *, workspace: str | None) -> dict[str, object]:
        """Ship the keyring-facing evidence once so the resident can read saved policy itself.

        The resident runs the same non-consuming probes this class composes in
        ``resolve_policy_decision_lookup`` (direct, exact-command and memory ids,
        portable Git workspace, most restrictive wins) over one store connection,
        deriving the candidate ids from the tool-call subject.

        A workspace whose identity nothing settles raises rather than shipping
        evidence without it: the caller then leaves the read to the
        ``policy_lookup`` effect, which answers through
        ``resolve_policy_decision_lookup`` and its restrictive-only fallback.
        """
        evidence = self.policy_lookup_evidence()
        lookup: dict[str, object] = {
            "store_path": str(self.path),
            "guard_home": str(self.guard_home),
            "now": evidence.now,
            "portable_workspace": self._portable_project_workspace(workspace),
            "integrity_state": evidence.integrity_state,
            "integrity_key_b64": evidence.integrity_key_b64,
            "integrity_key_id": evidence.integrity_key_id,
            "local_once_integrity_key_b64": evidence.local_once_integrity_key_b64,
            "local_once_integrity_key_id": evidence.local_once_integrity_key_id,
            "policy_bundle_decision_identities": evidence.policy_bundle_decision_identities,
            "degraded_trust_status": evidence.degraded_trust_status,
            "diagnostic_empty": not evidence.has_saved_rows,
        }
        return lookup

    def resolve_policy_decision_lookup(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
        local_once_only: bool = False,
    ) -> PolicyDecisionLookupResult:
        """Resolve the lookup with this clone's portable project identity composed in.

        A workspace with no portable identity resolves locally, because there
        is no portable half to compose. A workspace whose identity nothing
        settles is different: the portable half exists and could not be read,
        and because composition takes the most restrictive of the two, running
        the local lookup alone there would let a saved local allow take effect
        where a portable block had been winning. Such a workspace therefore
        gets the local lookup with only its restrictive part kept, consuming
        nothing, so the caller is asked again rather than silently allowed.
        """
        if local_once_only:
            portable_workspace = None
        else:
            try:
                portable_workspace = self._portable_project_workspace(workspace)
            except ProjectIdentityError:
                unread = super().resolve_policy_decision_lookup(
                    harness,
                    artifact_id,
                    artifact_hash=artifact_hash,
                    workspace=workspace,
                    publisher=publisher,
                    now=now,
                    runtime_exact_match_context=runtime_exact_match_context,
                    consume_one_shot=False,
                    local_once_only=False,
                )
                return cast("PolicyDecisionLookupResult", _restrictive_only_lookup(unread))
        if portable_workspace is None:
            return super().resolve_policy_decision_lookup(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=consume_one_shot,
                local_once_only=local_once_only,
            )

        # Portable Git metadata is classification, not authentication: it lives
        # inside the workspace and can be forged by that workspace. The resident
        # therefore previews the portable selector without consuming it, discards
        # any one-shot or permission-lowering decision it carries, composes that
        # with the local preview most restrictive, and only then claims the
        # effective allow — all over one store connection, under its own write
        # lock. Composing here instead would make Python choose the verdict and
        # would leave a window between the preview and the claim.
        evidence = self.policy_lookup_evidence(now=now, claim_binding=consume_one_shot)
        if evidence.degraded_trust_status is not None:
            return {
                "decision": None,
                "ignored_local_integrity": None,
                "trust_status": evidence.degraded_trust_status,
                "authority_revision": _DEGRADED_AUTHORITY_REVISION,
            }
        request = self.policy_decision_lookup_request(
            evidence,
            harness=harness,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
            portable_workspace=portable_workspace,
        )
        return cast(
            "PolicyDecisionLookupResult",
            self.send_policy_decision_lookup(request, required_feature=_PORTABLE_COMPOSITION),
        )

    def _portable_project_workspace(self, workspace: str | None) -> str | None:
        """The identity to probe under, or ``None`` when the workspace has none.

        A workspace whose identity nothing settles raises
        ``ProjectIdentityError`` rather than answering ``None``, because a
        probe sent without the identity reads only local authority.
        """
        if not isinstance(workspace, str) or not workspace.strip():
            return None
        normalized = workspace.strip()
        if is_portable_project_identity(normalized):
            return normalized
        return resolve_portable_project_identity(normalized, guard_home=self.guard_home)

    def _portable_probe_workspace(self, workspace: str | None) -> tuple[str | None, bool]:
        """The identity to probe under, and whether it was left unread."""
        try:
            return self._portable_project_workspace(workspace), False
        except ProjectIdentityError:
            return None, True
