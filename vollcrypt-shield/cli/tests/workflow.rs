use std::process::{Command, Output};

fn shield(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vollcrypt-shield"))
        .args(arguments)
        .output()
        .unwrap()
}

fn value(path: &std::path::Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn monitor_folder_creates_a_complete_dry_run_setup() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("project");
    let state = directory.path().join("state");
    let config = directory.path().join("shield.toml");
    let break_glass = directory.path().join("offline-break-glass.seed");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("app.conf"), b"approved").unwrap();

    let setup = shield(&[
        "monitor-folder",
        "--root",
        value(&root),
        "--state-dir",
        value(&state),
        "--config",
        value(&config),
        "--break-glass-key",
        value(&break_glass),
    ]);
    assert!(setup.status.success(), "{setup:?}");
    let setup_json: serde_json::Value = serde_json::from_slice(&setup.stdout).unwrap();
    assert_eq!(setup_json["scope"], "default");
    assert_eq!(setup_json["policyMode"], "dry-run");
    assert!(config.is_file());
    assert!(break_glass.is_file());
    assert!(state.join("snapshots/default.snapshot.cbor").is_file());

    let verified = shield(&["verify", "--config", value(&config), "--scope", "default"]);
    assert!(verified.status.success(), "{verified:?}");
    let repeated = shield(&[
        "monitor-folder",
        "--root",
        value(&root),
        "--state-dir",
        value(&state),
        "--config",
        value(&config),
        "--break-glass-key",
        value(&break_glass),
    ]);
    assert!(!repeated.status.success());
}

#[test]
fn multiple_folders_can_be_added_and_verified_together() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first project");
    let second = directory.path().join("second project");
    let state = directory.path().join("state");
    let config = directory.path().join("shield.toml");
    let break_glass = directory.path().join("offline-break-glass.seed");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    std::fs::write(first.join("app.conf"), b"approved-first").unwrap();
    std::fs::write(second.join("app.conf"), b"approved-second").unwrap();

    let setup = shield(&[
        "monitor-folder",
        "--root",
        value(&first),
        "--state-dir",
        value(&state),
        "--config",
        value(&config),
        "--break-glass-key",
        value(&break_glass),
        "--scope",
        "first",
    ]);
    assert!(setup.status.success(), "{setup:?}");

    let added = shield(&[
        "add-folder",
        "--config",
        value(&config),
        "--root",
        value(&second),
        "--scope",
        "second",
    ]);
    assert!(added.status.success(), "{added:?}");
    let added: serde_json::Value = serde_json::from_slice(&added.stdout).unwrap();
    assert_eq!(added["scopeCount"], 2);
    assert_eq!(added["baselineRequired"], true);
    assert_eq!(added["next"]["command"], "baseline");
    assert_eq!(added["next"]["scope"], "second");

    let baseline = shield(&["baseline", "--config", value(&config), "--scope", "second"]);
    assert!(baseline.status.success(), "{baseline:?}");

    let verified = shield(&["verify-all", "--config", value(&config)]);
    assert!(verified.status.success(), "{verified:?}");
    let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified["match"], true);
    assert_eq!(verified["scopeCount"], 2);
    assert_eq!(verified["results"].as_array().unwrap().len(), 2);

    std::fs::write(second.join("app.conf"), b"tampered").unwrap();
    let changed = shield(&["verify-all", "--config", value(&config)]);
    assert!(!changed.status.success());
    let changed: serde_json::Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_eq!(changed["match"], false);
    assert_eq!(changed["results"][0]["match"], true);
    assert_eq!(changed["results"][1]["match"], false);

    let overlap = shield(&[
        "add-folder",
        "--config",
        value(&config),
        "--root",
        value(&second),
        "--scope",
        "duplicate-root",
    ]);
    assert!(!overlap.status.success());
}

#[test]
fn baseline_verify_and_status_workflow_is_fail_safe() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("watched");
    let state = directory.path().join("state");
    let config = directory.path().join("shield.toml");
    let break_glass = directory.path().join("offline-break-glass.seed");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("app.conf"), b"approved").unwrap();

    let generated = shield(&[
        "config-example",
        "--root",
        value(&root),
        "--state-dir",
        value(&state),
        "--output",
        value(&config),
    ]);
    assert!(generated.status.success(), "{:?}", generated);

    let initialized = shield(&[
        "init",
        "--config",
        value(&config),
        "--break-glass-key",
        value(&break_glass),
    ]);
    assert!(initialized.status.success(), "{:?}", initialized);
    assert!(break_glass.is_file());

    let baseline = shield(&["baseline", "--config", value(&config), "--scope", "default"]);
    assert!(baseline.status.success(), "{:?}", baseline);
    let premature_activation = shield(&[
        "policy-activate",
        "--config",
        value(&config),
        "--scope",
        "default",
    ]);
    assert!(!premature_activation.status.success());

    let enrollment = directory.path().join("enrollment.cbor");
    let enrollment_export = shield(&[
        "fleet-enrollment-request",
        "--config",
        value(&config),
        "--label",
        "test-node",
        "--output",
        value(&enrollment),
    ]);
    assert!(enrollment_export.status.success(), "{enrollment_export:?}");
    assert!(enrollment.is_file());

    let summary = directory.path().join("summary-1.cbor");
    let summary_export = shield(&[
        "fleet-summary",
        "--config",
        value(&config),
        "--scope",
        "default",
        "--epoch",
        "1",
        "--output",
        value(&summary),
    ]);
    assert!(summary_export.status.success(), "{summary_export:?}");
    assert!(summary.is_file());
    let summary_output: serde_json::Value = serde_json::from_slice(&summary_export.stdout).unwrap();
    assert_eq!(summary_output["match"], true);

    let offline_package = directory.path().join("enrollment.vcsp");
    let packed = shield(&[
        "offline-pack",
        "--config",
        value(&config),
        "--kind",
        "fleet-enrollment",
        "--channel",
        "fleet-enrollment",
        "--input",
        value(&enrollment),
        "--sequence",
        "1",
        "--output",
        value(&offline_package),
    ]);
    assert!(packed.status.success(), "{packed:?}");

    let unpacked = directory.path().join("unpacked-enrollment.cbor");
    let unpack = shield(&[
        "offline-unpack",
        "--package",
        value(&offline_package),
        "--expected-public-key",
        value(&state.join("keys/agent.public")),
        "--expected-sequence",
        "1",
        "--output",
        value(&unpacked),
    ]);
    assert!(unpack.status.success(), "{unpack:?}");
    assert_eq!(
        std::fs::read(unpacked).unwrap(),
        std::fs::read(enrollment).unwrap()
    );

    std::fs::write(root.join("app.conf"), b"changed").unwrap();

    let verified = shield(&["verify", "--config", value(&config), "--scope", "default"]);
    assert!(!verified.status.success());
    assert_eq!(std::fs::read(root.join("app.conf")).unwrap(), b"changed");
    let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["match"], false);
    assert_eq!(report["outcomes"][0]["dry-run"], "app.conf");

    let activated = shield(&[
        "policy-activate",
        "--config",
        value(&config),
        "--scope",
        "default",
    ]);
    #[cfg(not(windows))]
    assert!(activated.status.success(), "{:?}", activated);
    #[cfg(windows)]
    {
        if activated.status.success() {
            assert_eq!(activated.stdout, b"activated default\n");
        } else {
            let error = String::from_utf8_lossy(&activated.stderr);
            assert!(
                error.contains("Windows")
                    && (error.contains("backup") || error.contains("active response")),
                "unexpected activation error: {error}"
            );
            assert!(
                std::fs::read_to_string(&config)
                    .unwrap()
                    .contains("mode = \"dry-run\"")
            );
        }
    }

    let status = shield(&["status", "--config", value(&config), "--scope", "default"]);
    assert!(status.status.success(), "{:?}", status);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["scope"], "default");
    assert_eq!(status["contained"], false);
    assert!(status["audit_records"].as_u64().unwrap() >= 4);

    let dashboard = shield(&[
        "dashboard",
        "--config",
        value(&config),
        "--scope",
        "default",
        "--once",
        "--no-color",
    ]);
    assert!(dashboard.status.success(), "{dashboard:?}");
    let dashboard = String::from_utf8(dashboard.stdout).unwrap();
    assert!(dashboard.contains("Vollcrypt Shield - Local Integrity Dashboard"));
    assert!(dashboard.contains("Status          : MONITORING"));
    assert!(dashboard.contains("Response mode   :"));
    assert!(dashboard.contains("Recent notifications"));

    let tui = shield(&[
        "tui",
        "--config",
        value(&config),
        "--scope",
        "default",
        "--no-color",
    ]);
    assert!(!tui.status.success());
    assert!(tui.stdout.is_empty());
    let error = String::from_utf8(tui.stderr).unwrap();
    assert!(error.contains("interactive terminal"));
    assert!(!error.contains("\x1b["));
}
