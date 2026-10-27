"""Cloud Review sync health, read by tests."""

from __future__ import annotations

from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable, unavailable_outbox_status
from codex_plugin_scanner.guard.runtime.cloud_review_event_delivery import CLOUD_REVIEW_EVENT_PROTOCOL_VERSION
from codex_plugin_scanner.guard.runtime.cloud_review_sync import _load_sync_state, _now
from codex_plugin_scanner.guard.store import GuardStore


def cloud_review_sync_status(store: GuardStore) -> dict[str, object]:
    """Return Cloud Review outbox and delivery health."""
    state = _load_sync_state(store)
    profile = store.get_cloud_sync_profile()
    workspace_id = profile.get("workspace_id") if isinstance(profile, dict) else None
    try:
        binding = store.get_review_event_oauth_binding()
        if binding is not None:
            outbox = store.review_event_outbox_status(
                now=_now(),
                oauth_subject_hash=binding["oauth_subject_hash"],
                workspace_id=binding["workspace_id"],
                machine_id=binding["machine_id"],
                machine_installation_id=binding["machine_installation_id"],
            )
        else:
            outbox = store.review_event_outbox_status(
                now=_now(),
                workspace_id=workspace_id,
            )
    except NativeGuardStoreUnavailable as error:
        outbox = unavailable_outbox_status(error)
    return {
        "state": state.get("state") or "not_configured",
        "last_sync_at": state.get("last_sync_at"),
        "last_success_at": state.get("last_success_at"),
        "last_error": state.get("last_error"),
        "synced_count": state.get("synced_count", 0),
        "rejected_count": state.get("rejected_count", 0),
        "outbox": outbox,
        "oauth_source": store.guard_source,
        "protocol_version": CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
        "protocolVersion": CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
    }
