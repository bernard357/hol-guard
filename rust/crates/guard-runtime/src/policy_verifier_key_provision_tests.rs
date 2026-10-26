use super::{provision_verifier_key, VerifierKeyProvision};
use guard_policy_snapshot::derive_verifier_key;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "hol-guard-verifier-key-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn key_path(state_base: &std::path::Path) -> PathBuf {
    state_base.join("policy-verifier.key")
}

#[test]
fn provisioning_writes_the_derived_key_once() {
    let state_base = root();
    let master = [7u8; 32];
    assert_eq!(
        provision_verifier_key(&state_base, &master),
        Ok(VerifierKeyProvision::Created)
    );
    let written = fs::read(key_path(&state_base)).unwrap();
    assert_eq!(written, derive_verifier_key(&master).to_vec());
    // The master itself must never reach the filesystem.
    assert_ne!(written, master.to_vec());
    assert_eq!(
        provision_verifier_key(&state_base, &master),
        Ok(VerifierKeyProvision::Verified)
    );
    fs::remove_dir_all(&state_base).unwrap();
}

#[test]
fn provisioning_leaves_no_temporary_behind() {
    let state_base = root();
    provision_verifier_key(&state_base, &[9u8; 32]).unwrap();
    let names: Vec<String> = fs::read_dir(&state_base)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["policy-verifier.key".to_owned()]);
    fs::remove_dir_all(&state_base).unwrap();
}

#[test]
fn a_changed_master_never_replaces_the_existing_key() {
    let state_base = root();
    let first = [1u8; 32];
    provision_verifier_key(&state_base, &first).unwrap();
    assert_eq!(
        provision_verifier_key(&state_base, &[2u8; 32]),
        Err("native_policy_verifier_key_mismatch".to_owned())
    );
    // The original key survives a rejected master.
    assert_eq!(
        fs::read(key_path(&state_base)).unwrap(),
        derive_verifier_key(&first).to_vec()
    );
    fs::remove_dir_all(&state_base).unwrap();
}

#[test]
fn a_master_of_the_wrong_length_is_refused_before_any_write() {
    let state_base = root();
    assert_eq!(
        provision_verifier_key(&state_base, &[3u8; 16]),
        Err("native_policy_verifier_master_invalid".to_owned())
    );
    assert!(!state_base.exists());
}

#[test]
fn an_oversized_key_file_is_reported_without_waiting() {
    let state_base = root();
    provision_verifier_key(&state_base, &[4u8; 32]).unwrap();
    // Longer than a key: not a partial write, so no retry window applies.
    fs::write(key_path(&state_base), [5u8; 40]).unwrap();
    assert_eq!(
        provision_verifier_key(&state_base, &[4u8; 32]),
        Err("native_policy_verifier_key_invalid".to_owned())
    );
    fs::remove_dir_all(&state_base).unwrap();
}
