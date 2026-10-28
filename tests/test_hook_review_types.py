"""Tests for shared hook-review typed API."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.hook_review_types import (
    HookOutputSummary,
    HookReviewRequest,
    HookSourceFileRef,
)


class TestHookReviewRequestImmutability:
    def test_frozen_dataclass(self) -> None:
        request = HookReviewRequest(
            harness="pi",
            event_name="PostToolUse",
            payload={},
            payload_kind="inline",
            config_path=None,
            cwd=Path("/workspace"),
            home_dir=Path("/home"),
            guard_home=Path("/guard"),
            source_scope="project",
        )
        try:
            request.harness = "codex"  # type: ignore[misc]
        except AttributeError:
            pass
        else:
            raise AssertionError("HookReviewRequest should be frozen")

    def test_source_ref_optional(self) -> None:
        request = HookReviewRequest(
            harness="pi",
            event_name="PreToolUse",
            payload={},
            payload_kind="inline",
            config_path=None,
            cwd=None,
            home_dir=Path("/home"),
            guard_home=Path("/guard"),
            source_scope="project",
        )
        assert request.source_ref is None
        assert request.output_summary is None


class TestHookSourceFileRefDefaults:
    def test_adapter_stat_defaults_to_empty(self) -> None:
        ref = HookSourceFileRef(
            version=1,
            path="src/foo.ts",
            output_sha256="abc",
            output_chars=100,
        )
        assert ref.adapter_stat == {}
        assert ref.tool_input_path is None

    def test_adapter_stat_can_be_set(self) -> None:
        ref = HookSourceFileRef(
            version=1,
            path="src/foo.ts",
            output_sha256="abc",
            output_chars=100,
            tool_input_path="src/foo.ts",
            adapter_stat={"size": 100, "mtimeMs": 1760000000000},
        )
        assert ref.adapter_stat == {"size": 100, "mtimeMs": 1760000000000}


class TestHookOutputSummaryDefaults:
    def test_optional_fields_default_none(self) -> None:
        summary = HookOutputSummary(
            text_excerpt="hello",
            excerpt_truncated=False,
            output_sha256="abc",
            output_chars=5,
        )
        assert summary.content_items_seen is None
        assert summary.object_keys_seen is None
        assert summary.max_depth_seen is None
