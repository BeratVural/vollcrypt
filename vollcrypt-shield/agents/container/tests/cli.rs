use std::path::Path;
use std::process::Command;

use serde_json::json;
use sha2::{Digest, Sha256};

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

#[test]
fn cli_initializes_baselines_and_verifies_an_oci_layout() {
    let directory = tempfile::tempdir().unwrap();
    let layout = directory.path().join("layout");
    let state = directory.path().join("state");
    create_layout(&layout);
    let binary = env!("CARGO_BIN_EXE_vollcrypt-shield-container");

    let initialized = Command::new(binary)
        .args(["init", "--state-dir"])
        .arg(&state)
        .args(["--scope", "cli-image"])
        .output()
        .unwrap();
    assert!(initialized.status.success());
    assert!(
        String::from_utf8(initialized.stdout)
            .unwrap()
            .contains("initialized")
    );

    let baseline = Command::new(binary)
        .args(["baseline", "--state-dir"])
        .arg(&state)
        .arg("--layout")
        .arg(&layout)
        .output()
        .unwrap();
    assert!(baseline.status.success());

    let duplicate = Command::new(binary)
        .args(["baseline", "--state-dir"])
        .arg(&state)
        .arg("--layout")
        .arg(&layout)
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(
        String::from_utf8(duplicate.stderr)
            .unwrap()
            .contains("--replace")
    );

    let verified = Command::new(binary)
        .args(["verify", "--state-dir"])
        .arg(&state)
        .arg("--layout")
        .arg(&layout)
        .output()
        .unwrap();
    assert!(verified.status.success());
    assert!(
        String::from_utf8(verified.stdout)
            .unwrap()
            .contains("\"match\"")
    );

    let digest = format!("sha256:{}", "a".repeat(64));
    let policy = Command::new(binary)
        .args(["approve-docker", "--state-dir"])
        .arg(&state)
        .args(["--image-digest", &digest])
        .output()
        .unwrap();
    assert!(policy.status.success());
    assert!(String::from_utf8(policy.stdout).unwrap().contains(&digest));

    let duplicate = Command::new(binary)
        .args(["approve-docker", "--state-dir"])
        .arg(&state)
        .args(["--image-digest", &digest])
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(
        String::from_utf8(duplicate.stderr)
            .unwrap()
            .contains("--replace")
    );

    let audit = Command::new(binary)
        .args(["runtime-audit-verify", "--state-dir"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(audit.status.success());
    assert!(
        String::from_utf8(audit.stdout)
            .unwrap()
            .contains("\"records\": 0")
    );

    let containerd_policy = Command::new(binary)
        .args(["approve-containerd", "--state-dir"])
        .arg(&state)
        .args(["--namespace", "k8s.io", "--image-digest", &digest])
        .output()
        .unwrap();
    assert!(containerd_policy.status.success());
    assert!(
        String::from_utf8(containerd_policy.stdout)
            .unwrap()
            .contains("k8s.io")
    );

    let containerd_audit = Command::new(binary)
        .args(["runtime-audit-verify", "--state-dir"])
        .arg(&state)
        .args(["--runtime", "containerd"])
        .output()
        .unwrap();
    assert!(containerd_audit.status.success());
    assert!(
        String::from_utf8(containerd_audit.stdout)
            .unwrap()
            .contains("\"records\": 0")
    );

    let sidecar_evidence = directory.path().join("sidecar-evidence.json");
    std::fs::write(
        &sidecar_evidence,
        format!(
            "{{\"version\":1,\"podUid\":\"pod-cli\",\"namespace\":\"default\",\"containerName\":\"app\",\"imageDigest\":\"{}\"}}",
            digest
        ),
    )
    .unwrap();
    let sidecar_state = directory.path().join("sidecar-state");
    let initialized_sidecar = Command::new(binary)
        .args(["init", "--state-dir"])
        .arg(&sidecar_state)
        .args(["--scope", "sidecar-cli"])
        .output()
        .unwrap();
    assert!(initialized_sidecar.status.success());
    let approve_sidecar = Command::new(binary)
        .args(["approve-sidecar", "--state-dir"])
        .arg(&sidecar_state)
        .args([
            "--binding",
            "default/app",
            "--image-digest",
            digest.as_str(),
        ])
        .output()
        .unwrap();
    assert!(approve_sidecar.status.success());
    assert!(
        String::from_utf8(approve_sidecar.stdout)
            .unwrap()
            .contains("\"guaranteeLevel\": \"constrained\"")
    );

    let check = Command::new(binary)
        .args(["sidecar-check", "--state-dir"])
        .arg(&sidecar_state)
        .arg("--evidence-file")
        .arg(&sidecar_evidence)
        .output()
        .unwrap();
    assert!(check.status.success());
    let check_output = String::from_utf8(check.stdout).unwrap();
    assert!(check_output.contains("\"integrationMode\": \"sidecar\""));
    assert!(check_output.contains("\"guaranteeLevel\": \"constrained\""));

    let sidecar_audit = Command::new(binary)
        .args(["runtime-audit-verify", "--state-dir"])
        .arg(&sidecar_state)
        .args(["--runtime", "sidecar"])
        .output()
        .unwrap();
    assert!(sidecar_audit.status.success());
    assert!(
        String::from_utf8(sidecar_audit.stdout)
            .unwrap()
            .contains("\"records\": 3")
    );
}

fn create_layout(root: &Path) {
    std::fs::create_dir_all(root.join("blobs/sha256")).unwrap();
    std::fs::write(
        root.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let config = br#"{"architecture":"amd64","os":"linux"}"#;
    let layer = b"cli-layer";
    let config_descriptor = write_blob(root, "application/vnd.oci.image.config.v1+json", config);
    let layer_descriptor = write_blob(root, "application/vnd.oci.image.layer.v1.tar", layer);
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": config_descriptor,
        "layers": [layer_descriptor]
    }))
    .unwrap();
    let manifest_descriptor = write_blob(root, OCI_MANIFEST, &manifest);
    std::fs::write(
        root.join("index.json"),
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "manifests": [manifest_descriptor]
        }))
        .unwrap(),
    )
    .unwrap();
}

fn write_blob(root: &Path, media_type: &str, bytes: &[u8]) -> serde_json::Value {
    let digest = hex::encode(Sha256::digest(bytes));
    std::fs::write(root.join(format!("blobs/sha256/{digest}")), bytes).unwrap();
    json!({
        "mediaType": media_type,
        "digest": format!("sha256:{digest}"),
        "size": bytes.len()
    })
}
