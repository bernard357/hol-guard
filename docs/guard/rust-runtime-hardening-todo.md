# HOL Guard native runtime hardening TODO

Status: canonical follow-up backlog, tracked on `main`. Reconciled 2026-10-28
against `main` at `1aed1f43fb`, shipping as 3.58.0.

The program was originally planned on a `release/3.0` branch. It did not land
that way: every item below that is marked done shipped through ordinary PRs on
`main`. `release/3.0` is now 3,629 commits behind `main` and holds 8 commits
that were never merged; it is historical, not a working branch.

## Execution rules

- Work from `main`. `release/3.0` is frozen history, not a base.
- PreToolUse is native-authoritative. `runtime_transition_admission.py` admits a
  native runtime only after the native edge answers a known-allow and a
  known-deny probe and its own receipts reconcile against the runtime identity,
  policy generation and policy digest. Python checks receipts; it never
  recomputes a verdict.
- Rust owns authority. Retained Python is control, transport, presentation or
  non-authoritative persistence, never a second evaluator.
- Native unavailability fails closed. `hook_bridge_fallback.rs` records every
  hand-off to Python so the remaining count is visible and can be driven to zero.
- Every task needs code, tests, installed-artifact evidence, and matching
  documentation.
- Any security-lowering Python/Rust mismatch blocks authority.
- Never persist raw commands, prompts, output, paths, endpoints, database
  strings, environment values, secrets, tokens, or proofs.
- Delete replaced dead Python code; retain only named supported Python
  control/reference paths exercised in CI.

## PR 1: Source of truth and executable contracts

- [x] NRH-T001 reconcile merged Rust PRs, crates, workflows, packaging, transport, authority, and defaults;
- [x] NRH-T002 update migration PRD/TODO to current architecture;
- [x] NRH-T003 add protocol/admission ADR;
- [x] NRH-T004 add native/daemon failure ADR;
- [x] NRH-T005 add same-user/DoS/crash/fallback threat-model delta;
- [x] NRH-T006 add executable fail-safe matrix;
- [x] NRH-T007 ratify exact emergency-safe profile;
- [x] NRH-T008 add stable public native/daemon reason codes;
- [x] NRH-T009 add capability ownership and Python-removal manifest;
- [x] NRH-T010 add contract validation tests without changing authority.

## PR 2: Protocol v2, authentication, and bounded admission

- [x] NRH-T020 define request envelope with protocol, request ID/digest, operation, size, deadline, runtime/rule/policy identities — `resident_protocol.rs` (`ResidentRequestV1`, `ResidentOperationV1`, `capabilities()`);
- [x] NRH-T021 define request-bound response envelope and fixed overload response — `resident_protocol.rs` (`encode_response`, `error_response`, `safe_error_response`), `resident_transport.rs::write_overload` answering the fixed `native_overloaded`;
- [x] NRH-T022 reject duplicate/trailing/invalid UTF-8/deep/wide/overlong/unsupported structures before evaluation — `strict_json.rs`, `strict_json_value.rs`, reached through `resident_protocol::strict_json_value`;
- [x] NRH-T023 enforce operation-specific frame caps before allocation — `lib.rs` (`AUTHENTICATED_PREFETCH_BYTES`, per-operation caps) read before the payload is accepted;
- [x] NRH-T024 enforce authentication/header/payload/evaluation/write deadlines — `lib.rs` (`AUTH_TIMEOUT`, `HEADER_TIMEOUT`, `PAYLOAD_TIMEOUT`, `RESPONSE_TIMEOUT`), applied in `resident_transport.rs`; `hardening.rs::TOTAL_REQUEST_BUDGET` bounds the whole request;
- [ ] NRH-T025 add cross-language golden vectors and strict Python response binding;
- [x] NRH-T026 add POSIX mutual authentication while preserving `0700` directory and `0600` socket defenses — `resident_peer_identity.rs` reads the peer uid/gid from the kernel (`SO_PEERCRED` on Linux, `getpeereid` elsewhere); `resident_endpoint.rs` keeps the `0700` directory and proves cleanup does not follow a replacement symlink;
- [ ] NRH-T027 replace handwritten first-party HMAC with an audited minimal crate. In flight: `resident_auth_crypto.rs`, `daemon_policy_authority.rs`, `package_intent_parser.rs` and `local_supply_chain.rs` move to the RustCrypto `hmac` crate, each pinned to RFC 4231 or Python-computed vectors; mark this done when that change merges. `guard-policy-snapshot/src/policy_snapshot_crypto.rs` deliberately keeps its own implementation: it zeroizes its key block, pads and intermediate digest, which the crate does not;
- [ ] NRH-T028 rotate/clear per-process auth material and prove it never reaches argv/env/files/logs/payloads;
- [x] NRH-T029 separate small handshake and authentication-failure budgets — `lib.rs` sizes the handshake lane (`AUTH_WORKERS`, `AUTH_QUEUE_CAPACITY`, `AUTH_QUEUE_CAPACITY_MAX`) apart from the evaluation lane (`EVALUATION_WORKERS`, `EVALUATION_QUEUE_CAPACITY`);
- [x] NRH-T030 remove blocking permit wait from accept loop — `resident_transport_service.rs` accepts and hands off; `resident_transport.rs` answers `native_overloaded` on `TrySendError::Full` rather than blocking an auth worker;
- [x] NRH-T031 use fixed workers and bounded queue/executor — `resident_worker_pool.rs` (`spawn_workers`, `drain`) over the clamped counts in `lib.rs`;
- [x] NRH-T032 reserve lifecycle capacity, use deadline-aware admission and RAII release — `native_runtime_admission.rs`, `policy_enforcement_admission.rs`, `hardening.rs::request_expired`;
- [x] NRH-T033 handle transient accept errors with bounded backoff and fatal corruption with explicit exit — `hardening.rs` (`classify_io_error`, `accept_retry_delay` between 5 ms and 1 s); any unclassified error exits with `native_socket_accept_failed`;
- [x] NRH-T034 reject poisoned socket paths and remove only verified stale sockets — `resident_endpoint.rs::remove_if_same`, with tests that a replacement socket survives and a replacement symlink is not followed;
- [ ] NRH-T035 add malformed frame, slowloris, auth flood, low-descriptor, panic, capacity, and no-busy-spin tests — descriptor pressure, interrupted accept, idle-poll and capacity/overload cases exist (`hardening.rs` tests, `resident_transport_continuation_tests.rs`); malformed-frame, slowloris and auth-flood cases are still missing.

## PR 3: Supervision, fallback budgeting, and daemon fail-safe

- [x] NRH-T040 add explicit native health states and child-generation identity — `native_runtime_resilience.rs` (`NativeRuntimeHealthSnapshot`, the `native_record_*` transitions), `policy_integrity_generation.rs`, `managed_resident_lease_identity.rs`;
- [x] NRH-T041 retain child handle and detect exit without waiting for another hook — `managed_resident_supervisor.rs`, `managed_resident_exit.rs`;
- [ ] NRH-T042 prewarm outside the first hook;
- [ ] NRH-T043 add authenticated health operation outside normal evaluation capacity — the health model exists (`native_runtime_health_snapshot`); a dedicated authenticated health operation with its own capacity does not;
- [x] NRH-T044 restart asynchronously with single-flight, exponential backoff, jitter, bounded budget, and half-open probe — `resident_restart_budget.rs` (`RESTART_BACKOFF_BASE_MS`, `RESTART_BACKOFF_MAX_MS`, `MAX_RESTARTS_PER_WINDOW`, the budget lock for single flight), half-open probe in `native_runtime_resilience.rs`;
- [x] NRH-T045 add crash-loop circuit and zero-downtime rotation — the restart window above opens the circuit (`circuit_open` on the health snapshot); `managed_resident_handoff.rs` rotates under `HANDOFF_SHUTDOWN_TIMEOUT` while client heartbeats stay fresh;
- [x] NRH-T046 bind in-flight responses to their serving generation — `resident_state_supersession.rs`, `managed_resident_lease_retirement.rs`;
- [x] NRH-T047 add global one-shot semaphore/rate-limit/cooldown and bounded Python fallback queue — `native_runtime_resilience.rs` (`OneshotLease`, `native_oneshot_lease_acquire`);
- [x] NRH-T048 distinguish overload/unavailable/incompatible/auth/timeout/invalid/crash categories — the `native_record_*` family separates overload, resident failure, one-shot failure and integrity failure, each with its own reason label;
- [x] NRH-T049 prove 64 failures cannot create 64 processes — `resident_restart_budget_flood_tests.rs` charges the budget the way a spawn does and proves the three shapes a crash loop takes: 64 failures in a tight retry loop start three residents and retrying faster buys nothing back, a loop patient enough to wait out every backoff is held to a rate (against a simulated clock that rolls the restart window the way real time does, 64 failures buy 38 residents over five minutes rather than 64 processes), and 64 clients that miss the resident at once are charged one at a time under the budget lock;
- [x] NRH-T050 implement deterministic fail-safe behavior for every hook when daemon is unavailable — `hook_bridge_fallback.rs` settles the hook and records the hand-off with harness and fixed reason only;
- [ ] NRH-T051 allow only authenticated current emergency-safe profile during daemon failure;
- [ ] NRH-T052 add bounded daemon restart reservation and preserve approval/receipt/activity ordering;
- [ ] NRH-T053 add panic/kill/hang/stale endpoint/port/socket/binary/manifest/policy/disk/permission/crash-loop tests — stale endpoint, owner lock, retry and live failure cases exist (`managed_resident_live_failure_tests.rs`, `managed_resident_owner_lock_tests.rs`, `resident_state_discovery_tests.rs`); the rest are open;
- [ ] NRH-T054 add privacy-safe aggregate lifecycle journal and critical health state — `resident_failure_log.rs` records failures; an aggregate lifecycle journal does not exist.

## PR 4: Cross-platform installed-wheel and resource gates

- [ ] NRH-T060 run equivalent real-wheel suites on Ubuntu 22.04/24.04, macOS Intel/arm64, and Windows x64;
- [ ] NRH-T061 add CPython 3.10-3.14 smoke;
- [ ] NRH-T062 add pip/pipx/uv tool/offline/upgrade/downgrade/reinstall/rollback/Desktop/managed smoke;
- [ ] NRH-T063 run parity, mutation, overload, crash, daemon-failure, path, privacy, and performance on every Tier 1 target;
- [ ] NRH-T064 add Windows PowerShell/CMD, reparse/junction/UNC/device/long path/Job Object/lock/quarantine cases;
- [ ] NRH-T065 add macOS APFS case modes, aliases, links, mounts, socket paths, quarantine/signing/sleep cases;
- [ ] NRH-T066 add Linux static, path walk, bind/overlay, namespace/container, FD/cgroup/noexec/read-only/stale socket cases;
- [ ] NRH-T067 make explicit Linux arm64 and musl support decisions;
- [ ] NRH-T068 emit aggregate-only evidence and scan artifacts for prohibited data.

Partial coverage exists today in `nightly-native.yml`, `release-native-wheel.yml`,
`release-native-determinism.yml`, `mcp-amd64-native-validation.yml` and
`platform-arm-inventory.yml`. None of them is yet the equivalent-suite matrix
these items ask for.

## PR 5: Catastrophic-risk effect and detector parity

- [ ] NRH-T080 define versioned privacy-safe effect DTO and corpus version;
- [ ] NRH-T081 model sensitive read, network sink, subprocess/package execution, writes/deletion, DB/infra mutation, Guard tampering, confidence/scope/reversibility/containment/approval floor;
- [ ] NRH-T082 bind effects to request/parser/rule/policy identities;
- [ ] NRH-T083 keep durable correlation in Python and add read-then-exfil plus Guard-disable-then-retry sequences;
- [ ] NRH-T084 use more restrictive effect/action on mismatch;
- [ ] NRH-T085 expand secret/exfiltration corpus across credentials, shells, encodings, archives, cloud/GitHub/webhook/database/language clients;
- [ ] NRH-T086 prove no secret sample reaches responses/logs/diagnostics/metrics/artifacts/crashes;
- [ ] NRH-T087 add bounded native prompt-injection DTO/rules with documentation/fixture/quotation context parity;
- [ ] NRH-T088 scan untrusted repository/web/issue/PR/log/MCP/file output and expose tightening-only signals until parity;
- [ ] NRH-T089 add POSIX/PowerShell/CMD/language/Git/package/cloud mass-deletion effects and bounded scope estimation;
- [ ] NRH-T090 add destructive production DB, migration, backup, cloud DB, cluster/namespace/bucket/IAM/secret/resource-group effects;
- [ ] NRH-T091 add Guard tampering and flood-then-retry effects;
- [ ] NRH-T092 require 100% pause/deny on approved catastrophic corpora, zero unsafe downgrade, and safe-corpus false-pause <0.5%;
- [x] NRH-T093 retired. It asked to keep native PreToolUse allow authority disabled. The hot path moved to Rust and PreToolUse is native-authoritative; `runtime_transition_admission.py` proves a candidate runtime against a known-allow and a known-deny probe before admitting it. The Gauntlet and the benign gate, not this item, now hold the line on false pauses.

The command-effect side of this section is largely live in `guard-command`
(`local_supply_chain.rs`, `package_intent_parser.rs`, the `pretool/` route
modules). What is open is the versioned effect DTO, the corpus and the
measured parity gate, not the detection itself.

## PR 6: DX, observability, repair, and dead-code cleanup

- [x] NRH-T100 add stable native status model for CLI/dashboard/Desktop/MDM — `native_runtime_resilience.rs::NativeRuntimeHealthSnapshot`, surfaced through `native_runtime.py::native_runtime_health`;
- [ ] NRH-T101 add `hol-guard doctor --native` and `hol-guard runtime status --json` — `hol-guard guard doctor` and `hol-guard guard runtime [posture] --json` exist, and the health model is in place, but the posture command reports harness detections and advisories, not the native health snapshot, and `doctor` has no `--native` flag;
- [ ] NRH-T102 add idempotent native lifecycle repair and clear diagnosis for noexec/wrong wheel/unsupported/manifest/permission/stale endpoint/circuit/daemon — `codex_hook_repair_native.py` and the protection repair page cover part of this;
- [ ] NRH-T103 add bounded aggregate metrics for latency/size/cost/queue/overload/auth/fallback/timeout/crash/restart/circuit/mismatch;
- [ ] NRH-T104 add support-bundle redaction and privacy tests;
- [ ] NRH-T105 add plain-language pause copy and exact approve-once/target/pattern/contained/narrow/dry-run/edit/cancel options;
- [ ] NRH-T106 keep healthy safe operations silent and approval scope consistent across surfaces;
- [ ] NRH-T107 add local and managed native kill switches plus rollback playbook;
- [x] NRH-T108 generate static import/call graph and runtime import coverage for migration candidates;
- [ ] NRH-T109 delete dead duplicate Python implementations, including the unused `choose_post_tool_response` selector, plus its tests, imports, dependencies, package entries, flags, and shims;
- [x] NRH-T110 move reusable cases to language-neutral fixtures and add package-content/import-removal tests;
- [x] NRH-T111 publish Python LOC/dependency delta and require every retained reference backend to run in named CI.
- [x] NRH-T112 delete `choose_post_tool_response` after repository-wide static and dynamic caller proof;
- [ ] NRH-T113 delete replaced PostToolUse traversal, scanning, secure-read, hashing, and path-validation Python implementations in the same authority-cutover wave;
- [ ] NRH-T114 delete replaced command parsing and catastrophic-risk Python implementations only after cross-shell native authority gates pass;
- [ ] NRH-T115 remove dependencies and build/package metadata used only by deleted implementations;
- [x] NRH-T116 add installed-wheel tests proving removed private modules are absent and intentionally non-importable;
- [ ] NRH-T117 audit dynamic imports, entry points, plugin references, and string-based module loading before every deletion;
- [ ] NRH-T118 treat every unreachable or untested fallback as dead code rather than dormant rollback;
- [x] NRH-T119 prove dead-code package exclusion preserves the named pure-Python unsupported-platform and rollback configurations.

## PR 7: Supply chain, fuzz, chaos, soak, and opt-in gate

- [ ] NRH-T120 add Cargo advisory, source, license, duplication, and banned-crate gates — the repository has no `deny.toml` and runs no `cargo deny` or `cargo audit` job;
- [x] NRH-T121 generate Rust SBOM/provenance bound to every native wheel and verify staged/published wheel bytes — `publish.yml` writes the release toolchain SBOM and refuses to publish a wheel whose bytes do not verify against the release's `intoto.jsonl` provenance bundle;
- [ ] NRH-T122 add persistent frame/envelope/output/scanner/prompt/command/path/response fuzz targets and deterministic PR seeds — `fuzz.yml` runs ClusterFuzzLite over the Python package only; there are no Rust fuzz targets;
- [ ] NRH-T123 add 10,000 malformed frames, auth floods, 16 slow clients, 64 mixed clients, fallback saturation, daemon kills, disk/read-only/stale/low-FD chaos;
- [ ] NRH-T124 add 100,000-request soak, rotation, memory/handle/thread/process/socket leak gate;
- [ ] NRH-T125 measure installed adapter-to-decision p50/p95/p99/max, throughput, CPU, RSS, threads, handles, FDs, sockets, processes, queue, and fallback — `warm-path-latency.yml` and `rust-runtime-performance.yml` measure part of this;
- [ ] NRH-T126 enforce PR no-regression and documented-hardware absolute SLOs without weakening security;
- [ ] NRH-T127 complete independent security review and resolve all unsafe/unexplained mismatches;
- [x] NRH-T128 enable eligible PostToolUse `auto` by default only for verified bundled wheels, retaining explicit `off` and Python fallback;
- [x] NRH-T129 retired. It asked to keep PreToolUse allow authority disabled and retain the pure-Python rollback. PreToolUse is native-authoritative now; the pure-Python compatibility wheel stays for unsupported platforms and `off` remains the explicit rollback, which is what T119 and T128 pin.

## Final release gate

NHD-091–095 completed the ownership/graph/package proof for the cleanup
surface, and the resident Python runtime module it recorded as a deletion
candidate is gone. T109, T113, T114, T115, T117, and T118 remain open until a
separate authorized deletion wave removes the remaining replaced source and any
newly proven-dead implementation dependencies.

- [ ] all transport, overload, fallback, supervision, daemon-failure, privacy, cross-platform, catastrophic-risk, safe-autonomy, performance, fuzz, chaos, soak, artifact, review, and rollback gates pass;
- [ ] dead replaced Python code is removed and retained Python ownership is explicit;
- [x] a dedicated PR changes eligible PostToolUse source default to `auto` with installed-wheel and rollback evidence;
- [x] the program ships from `main`. The original "`release/3.0` remains unmerged to `main`" rule is retired: the work landed on `main` through ordinary PRs and `release/3.0` is historical.
