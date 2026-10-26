//! Cloud coverage must judge PATH order the way a new login shell sees it.
//!
//! Guard syncs coverage from processes that were not started by the user's
//! login shell, so their PATH lacks the shim directory the shell profile
//! prepends. Reporting every shim as bypassed in that case tells the workspace
//! a protected machine is unprotected.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use guard_command::shims::{self, ShimContext, ShimFacts};
use serde_json::Value;

fn facts(home: &str, path: &str) -> ShimFacts {
    let environ: BTreeMap<String, String> = [
        ("HOME".to_owned(), home.to_owned()),
        ("PATH".to_owned(), path.to_owned()),
        ("SHELL".to_owned(), "/bin/zsh".to_owned()),
    ]
    .into_iter()
    .collect();
    ShimFacts {
        environ,
        home: home.to_owned(),
        cwd: home.to_owned(),
        executable: "/usr/bin/python3".to_owned(),
        frozen: false,
        frozen_cli: String::new(),
        trusted_frozen_cli_paths: Vec::new(),
        python_version: (3, 12),
        import_root: home.to_owned(),
        argv0: None,
        windows: false,
        sqlite_connect_timeout_seconds: 5.0,
        now: "2026-10-26T00:00:00Z".to_owned(),
        shim_dir_transient: Some(false),
    }
}

fn write_executable(path: &Path) {
    fs::write(path, "#!/bin/sh\nexit 0\n").expect("write binary");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn names(coverage: &Value, key: &str) -> Vec<String> {
    coverage[key]
        .as_array()
        .expect("list")
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

#[test]
fn a_profile_staged_shim_is_reported_as_a_new_shell_will_see_it() {
    let scratch = tempfile::tempdir().expect("scratch");
    let root = fs::canonicalize(scratch.path()).expect("canonical scratch");
    let home = root.join("home");
    let real_bin = root.join("real-bin");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&real_bin).expect("real bin");
    write_executable(&real_bin.join("npm"));
    let home = home.to_string_lossy().into_owned();
    let guard_home = format!("{home}/.hol-guard");
    let process_path = format!("{}:/usr/bin:/bin", real_bin.display());
    let context = ShimContext::new(&guard_home, Some(&home), None, facts(&home, &process_path));

    shims::install_package_shims(&context, Some(&["npm".to_owned()]), Some(&process_path))
        .expect("install");
    shims::ensure_package_shim_path_in_shell_profile(&context).expect("profile");

    let status = shims::package_shim_status(&context, None).expect("status");
    assert_eq!(status["path_status"], "restart_required");

    let coverage = shims::package_shim_cloud_coverage(&context, None).expect("coverage");
    assert_eq!(names(&coverage, "protectedManagers"), ["npm"]);
    assert_eq!(coverage["pathActive"], true);
    assert_eq!(coverage["bypasses"], Value::Array(Vec::new()));
}

#[test]
fn a_shim_without_a_profile_entry_is_still_reported_as_bypassed() {
    let scratch = tempfile::tempdir().expect("scratch");
    let root = fs::canonicalize(scratch.path()).expect("canonical scratch");
    let home = root.join("home");
    let real_bin = root.join("real-bin");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&real_bin).expect("real bin");
    write_executable(&real_bin.join("npm"));
    let home = home.to_string_lossy().into_owned();
    let guard_home = format!("{home}/.hol-guard");
    let process_path = format!("{}:/usr/bin:/bin", real_bin.display());
    let context = ShimContext::new(&guard_home, Some(&home), None, facts(&home, &process_path));

    shims::install_package_shims(&context, Some(&["npm".to_owned()]), Some(&process_path))
        .expect("install");

    let coverage = shims::package_shim_cloud_coverage(&context, None).expect("coverage");
    assert!(names(&coverage, "protectedManagers").is_empty());
    assert_eq!(coverage["pathActive"], false);
    assert_eq!(coverage["bypasses"][0]["reason"], "path_inactive");
}

#[test]
fn an_appended_profile_stays_bypassed() {
    let scratch = tempfile::tempdir().expect("scratch");
    let root = fs::canonicalize(scratch.path()).expect("canonical scratch");
    let home = root.join("home");
    let real_bin = root.join("real-bin");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&real_bin).expect("real bin");
    write_executable(&real_bin.join("npm"));
    let home = home.to_string_lossy().into_owned();
    let guard_home = format!("{home}/.hol-guard");
    let process_path = format!("{}:/usr/bin:/bin", real_bin.display());
    let context = ShimContext::new(&guard_home, Some(&home), None, facts(&home, &process_path));

    shims::install_package_shims(&context, Some(&["npm".to_owned()]), Some(&process_path))
        .expect("install");
    shims::ensure_package_shim_path_in_shell_profile(&context).expect("profile");
    let staged = shims::package_shim_status(&context, None).expect("status");
    assert_eq!(staged["path_status"], "restart_required");
    let shim_dir = staged["shim_dir"].as_str().expect("shim dir");
    let profiles = staged["shell_profile_paths"].as_array().expect("profiles");
    assert!(!profiles.is_empty());
    for path in profiles {
        let path = path.as_str().expect("profile path");
        fs::write(path, format!("export PATH=\"$PATH:{shim_dir}\"\n")).expect("append");
    }

    let coverage = shims::package_shim_cloud_coverage(&context, None).expect("coverage");
    assert!(names(&coverage, "protectedManagers").is_empty());
    assert_eq!(coverage["pathActive"], false);
    assert_eq!(coverage["bypasses"][0]["manager"], "npm");
    assert_eq!(coverage["bypasses"][0]["reason"], "path_inactive");
}
