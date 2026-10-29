//! Entry points for the fuzz targets in `rust/fuzz`.
//!
//! Each function takes the bytes a fuzzer produces and feeds them to a real
//! parser on an untrusted boundary: the resident's request frame, a command
//! model request, a shell command, scanned text, a harness's Python-flavoured
//! JSON, prompt text, and the containment path screen. A target asserts
//! nothing beyond "this input does not crash the parser"; libFuzzer reports a
//! panic, an abort, a sanitizer finding, or a timeout.
//!
//! Only parsing and classification is reachable from here. No entry point
//! dispatches an operation, touches the store, writes a file, or starts a
//! process, so a fuzzing run cannot have an effect outside its own process.
//! Keep that true when adding one: a parser is fair game, an operation is not.
//!
//! The same functions replay the committed seed corpus as an ordinary test
//! (`fuzz_entry_tests.rs`), so a crash found by a campaign becomes a seed that
//! every pull request runs on the stable toolchain.

use std::time::{Duration, Instant};

/// The resident's request frame, as it arrives from a client: strict JSON
/// first, then the untagged request enum behind it.
pub fn resident_frame(data: &[u8]) {
    let Ok(value) = crate::resident_protocol::strict_json_value(data) else {
        return;
    };
    let _ = crate::strict_json::from_value::<crate::resident_protocol::ResidentRequestV1>(value);
}

/// A command model request: the envelope a harness sends, then the parse that
/// every command decision is built on.
pub fn command_request(data: &[u8]) {
    let Ok(request) = serde_json::from_slice::<guard_command::CommandModelRequestV1>(data) else {
        return;
    };
    if request.command.trim().is_empty() {
        return;
    }
    let _ = guard_command::parse_command(&request);
}

/// A shell command in one of the dialects Guard parses. The leading byte picks
/// the dialect so a fuzzer can reach all three without a structured input.
pub fn shell_command(data: &[u8]) {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    if text.trim().is_empty() {
        return;
    }
    let dialect = match *selector % 3 {
        0 => "bash",
        1 => "powershell",
        _ => "cmd",
    };
    let _ = guard_command::command_model::parse_shell_command(
        text,
        None,
        None,
        dialect,
        "shell_string",
        "fuzz",
        true,
    );
}

/// Text through the secret scanner, bounded so a pathological input fails the
/// target's own deadline rather than the campaign's.
pub fn scanner_text(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = guard_scanner::scan_text(
        text,
        true,
        false,
        1 << 20,
        Some(Instant::now() + Duration::from_secs(5)),
    );
}

/// Tool output as a harness writes it: JSON with CPython's own escapes and
/// duplicate-key rule.
pub fn python_json(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = guard_runtime_pyjson::parse_unique(text);
    let _ = guard_runtime_pyjson::parse_marking_lone_surrogates(text);
}

/// Prompt text through the injection detectors and the `guard run` request
/// extractor.
pub fn prompt_text(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = guard_command::prompt_analysis::detect_prompt_injection_requests(text);
    let _ = guard_command::prompt_analysis::extract_prompt_requests(text);
}

/// The containment path screen, which decides whether an argument points out
/// of the workspace a contained run may touch.
pub fn contained_path(data: &[u8]) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let _ = guard_command::contained_argv::evaluate("contained_target", &value);
}

/// One fuzz entry point: it takes the fuzzer's bytes and must not panic on any
/// of them.
pub type FuzzEntryPoint = fn(&[u8]);

/// Every entry point with the corpus directory it replays, so a new target
/// cannot be added without a seed corpus beside it.
pub const FUZZ_ENTRY_POINTS: &[(&str, FuzzEntryPoint)] = &[
    ("resident_frame", resident_frame),
    ("command_request", command_request),
    ("shell_command", shell_command),
    ("scanner_text", scanner_text),
    ("python_json", python_json),
    ("prompt_text", prompt_text),
    ("contained_path", contained_path),
];

#[cfg(test)]
#[path = "fuzz_entry_tests.rs"]
mod tests;
