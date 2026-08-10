use std::path::Path;
use std::process::{Command, Output};

use rusqlite::Connection;

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vollcrypt-shield-db"))
        .args(arguments)
        .output()
        .unwrap()
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn cli_creates_baseline_and_returns_two_for_drift() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("app.sqlite");
    let state = directory.path().join("state");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE settings (id INTEGER PRIMARY KEY, value TEXT NOT NULL);\
             INSERT INTO settings VALUES (1, 'approved');",
        )
        .unwrap();

    let initialized = run(&["init", "--state-dir", text(&state), "--scope", "settings"]);
    assert!(initialized.status.success());
    let baseline = run(&[
        "baseline",
        "--state-dir",
        text(&state),
        "--database",
        text(&database),
        "--table",
        "settings",
    ]);
    assert!(baseline.status.success());
    let verified = run(&[
        "verify",
        "--state-dir",
        text(&state),
        "--database",
        text(&database),
        "--table",
        "settings",
    ]);
    assert!(verified.status.success());

    connection
        .execute("UPDATE settings SET value = 'tampered' WHERE id = 1", [])
        .unwrap();
    let drift = run(&[
        "verify",
        "--state-dir",
        text(&state),
        "--database",
        text(&database),
        "--table",
        "settings",
    ]);
    assert_eq!(drift.status.code(), Some(2));
    let output: serde_json::Value = serde_json::from_slice(&drift.stdout).unwrap();
    assert_eq!(output["status"], "mismatch");
    assert_eq!(output["recordCount"], 1);
    assert_eq!(output["differences"].as_array().unwrap().len(), 1);
}

#[test]
fn cli_binds_explicit_db_guard_context_without_runtime_dependency() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("app.sqlite");
    let context = directory.path().join("db-guard-context.json");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            r#"CREATE TABLE settings (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
               INSERT INTO settings VALUES (1, 'approved');"#,
        )
        .unwrap();
    std::fs::write(
        &context,
        format!(
            r#"{{"formatVersion":1,"databaseId":"app/settings","kmsRouteId":"kms/app","encryptionPolicyDigest":"{}","keyEpoch":3}}"#,
            "ab".repeat(32)
        ),
    )
    .unwrap();

    let standalone = run(&["scan", "--database", text(&database), "--table", "settings"]);
    assert!(standalone.status.success());
    let enhanced = run(&[
        "--db-guard-context",
        text(&context),
        "scan",
        "--database",
        text(&database),
        "--table",
        "settings",
    ]);
    assert!(enhanced.status.success());
    let standalone: serde_json::Value = serde_json::from_slice(&standalone.stdout).unwrap();
    let enhanced: serde_json::Value = serde_json::from_slice(&enhanced.stdout).unwrap();
    assert_ne!(standalone["schemaHash"], enhanced["schemaHash"]);
    assert_ne!(standalone["root"], enhanced["root"]);
}
