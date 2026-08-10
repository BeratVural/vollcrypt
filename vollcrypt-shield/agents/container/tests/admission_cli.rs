use std::process::Command;

use serde_json::json;

#[test]
fn admission_cli_approves_pins_and_rejects_tags() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let review = directory.path().join("review.json");
    let binary = env!("CARGO_BIN_EXE_vollcrypt-shield-container");
    let digest = format!("sha256:{}", "a".repeat(64));

    assert!(
        Command::new(binary)
            .args(["init", "--state-dir"])
            .arg(&state)
            .args(["--scope", "admission-cli"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(binary)
            .args(["approve-admission", "--state-dir"])
            .arg(&state)
            .args([
                "--namespace",
                "production",
                "--image-digest",
                digest.as_str(),
            ])
            .status()
            .unwrap()
            .success()
    );

    write_review(&review, &format!("registry.example/app@{digest}"));
    let approved = Command::new(binary)
        .args(["admission-check", "--state-dir"])
        .arg(&state)
        .arg("--review")
        .arg(&review)
        .output()
        .unwrap();
    assert!(approved.status.success());
    assert!(
        String::from_utf8(approved.stdout)
            .unwrap()
            .contains("\"allowed\": true")
    );

    write_review(&review, "registry.example/app:latest");
    let denied = Command::new(binary)
        .args(["admission-check", "--state-dir"])
        .arg(&state)
        .arg("--review")
        .arg(&review)
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(2));
    assert!(
        String::from_utf8(denied.stdout)
            .unwrap()
            .contains("\"allowed\": false")
    );

    let audit = Command::new(binary)
        .args(["runtime-audit-verify", "--state-dir"])
        .arg(&state)
        .args(["--runtime", "admission"])
        .output()
        .unwrap();
    assert!(audit.status.success());
    assert!(
        String::from_utf8(audit.stdout)
            .unwrap()
            .contains("\"records\": 6")
    );
}

fn write_review(path: &std::path::Path, image: &str) {
    std::fs::write(
        path,
        serde_json::to_vec(&json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "cli-request",
                "namespace": "production",
                "operation": "CREATE",
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "spec": {
                        "containers": [{"name": "app", "image": image}]
                    }
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
}
