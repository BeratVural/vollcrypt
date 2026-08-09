#![forbid(unsafe_code)]

use ml_dsa::{MlDsa65, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vollcrypt_scan_core::{RuleSet, ScanReport, ScannedFile};

mod rule_signature;

use rule_signature::{RULE_PUBLIC_KEY_HEX, RULE_SIGNATURE_HEX};

pub const RULE_SET_ID: &str = "vollcrypt-shield-default";
pub const RULE_SET_VERSION: u32 = 1;
pub const OUTPUT_SCHEMA_VERSION: u32 = 1;

const RULE_DESCRIPTOR: &str = include_str!("../default_rules.json");
const RULE_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Classification Rules v1";

#[derive(Debug, thiserror::Error)]
pub enum ClassifierError {
    #[error("embedded classification rule signature is invalid")]
    InvalidRuleSignature,
    #[error("embedded classification rules are invalid: {0}")]
    InvalidRuleDocument(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleDocument {
    version: u32,
    private_extensions: Vec<String>,
    private_names: Vec<String>,
    secret_names: Vec<String>,
    secret_path_components: Vec<String>,
    deployment_prefixes: Vec<String>,
    deployment_path_components: Vec<String>,
    deployment_extensions: Vec<String>,
    deployment_names: Vec<String>,
    entrypoint_names: Vec<String>,
    entrypoint_suffixes: Vec<String>,
    lockfile_names: Vec<String>,
    private_key_markers: Vec<String>,
    credential_prefixes: Vec<String>,
    entropy_threshold: f64,
    entropy_min_bytes: u64,
    entropy_max_bytes: u64,
    critical_threshold: u8,
    important_threshold: u8,
    corroboration_bonus: u8,
    max_corroborating_rules: usize,
    confidence_cap: u8,
    scores: RuleScores,
    monitoring: MonitoringRules,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleScores {
    private_path: u8,
    secret_path: u8,
    deployment: u8,
    entrypoint: u8,
    lockfile: u8,
    private_content: u8,
    credential_content: u8,
    high_entropy: u8,
    default: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MonitoringRules {
    critical: MonitoringRule,
    important: MonitoringRule,
    standard: MonitoringRule,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MonitoringRule {
    mode: String,
    fallback_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Criticality {
    Standard,
    Important,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationReason {
    pub rule_id: String,
    pub detail: String,
    pub score: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationSuggestion {
    pub path: String,
    pub criticality: Criticality,
    pub confidence: u8,
    pub entropy_bits_per_byte: f64,
    pub reasons: Vec<ClassificationReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetMetadata {
    pub id: String,
    pub version: u32,
    pub sha256: String,
    pub update_mode: String,
    pub signature_algorithm: String,
    pub signing_key_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitoringGroupSuggestion {
    pub criticality: Criticality,
    pub monitoring_mode: String,
    pub periodic_fallback_secs: u64,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassifierOutput {
    pub schema_version: u32,
    pub rule_set: RuleSetMetadata,
    pub scan: ScanReport<ClassificationSuggestion>,
    pub monitoring_groups: Vec<MonitoringGroupSuggestion>,
}

impl ShieldClassifier {
    pub fn output(&self, scan: ScanReport<ClassificationSuggestion>) -> ClassifierOutput {
        let monitoring_groups = [
            (Criticality::Critical, &self.rules.monitoring.critical),
            (Criticality::Important, &self.rules.monitoring.important),
            (Criticality::Standard, &self.rules.monitoring.standard),
        ]
        .into_iter()
        .map(|(criticality, monitoring)| MonitoringGroupSuggestion {
            criticality,
            monitoring_mode: monitoring.mode.clone(),
            periodic_fallback_secs: monitoring.fallback_secs,
            paths: scan
                .findings
                .iter()
                .filter(|finding| finding.criticality == criticality)
                .map(|finding| finding.path.clone())
                .collect(),
        })
        .collect();
        ClassifierOutput {
            schema_version: OUTPUT_SCHEMA_VERSION,
            rule_set: self.metadata.clone(),
            scan,
            monitoring_groups,
        }
    }
}

#[derive(Debug)]
pub struct ShieldClassifier {
    metadata: RuleSetMetadata,
    rules: RuleDocument,
}

impl ShieldClassifier {
    pub fn new() -> Result<Self, ClassifierError> {
        let public_key = verify_rule_signature(RULE_DESCRIPTOR.as_bytes())?;
        let rules: RuleDocument = serde_json::from_str(RULE_DESCRIPTOR)
            .map_err(|error| ClassifierError::InvalidRuleDocument(error.to_string()))?;
        validate_rule_document(&rules)?;
        let mut digest = Sha256::new();
        digest.update(RULE_DESCRIPTOR.as_bytes());
        let mut key_digest = Sha256::new();
        key_digest.update(&public_key);
        Ok(Self {
            metadata: RuleSetMetadata {
                id: RULE_SET_ID.to_owned(),
                version: RULE_SET_VERSION,
                sha256: hex::encode(digest.finalize()),
                update_mode: "signed-compiled-in".to_owned(),
                signature_algorithm: "ML-DSA-65".to_owned(),
                signing_key_sha256: hex::encode(key_digest.finalize()),
            },
            rules,
        })
    }

    pub fn metadata(&self) -> &RuleSetMetadata {
        &self.metadata
    }
}

fn verify_rule_signature(descriptor: &[u8]) -> Result<Vec<u8>, ClassifierError> {
    let public_key =
        hex::decode(RULE_PUBLIC_KEY_HEX).map_err(|_| ClassifierError::InvalidRuleSignature)?;
    let signature =
        hex::decode(RULE_SIGNATURE_HEX).map_err(|_| ClassifierError::InvalidRuleSignature)?;
    let encoded_key = hybrid_array::Array::try_from(public_key.as_slice())
        .map_err(|_| ClassifierError::InvalidRuleSignature)?;
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_key);
    let encoded_signature = hybrid_array::Array::try_from(signature.as_slice())
        .map_err(|_| ClassifierError::InvalidRuleSignature)?;
    let signature = Signature::<MlDsa65>::decode(&encoded_signature)
        .ok_or(ClassifierError::InvalidRuleSignature)?;
    if !verifying_key.verify_with_context(descriptor, RULE_SIGNATURE_CONTEXT, &signature) {
        return Err(ClassifierError::InvalidRuleSignature);
    }
    Ok(public_key)
}

impl RuleSet for ShieldClassifier {
    type Finding = ClassificationSuggestion;

    fn analyze(&self, file: &ScannedFile<'_>) -> Vec<Self::Finding> {
        let path = file.relative_path.to_ascii_lowercase();
        let name = path.rsplit('/').next().unwrap_or(path.as_str());
        let extension = name.rsplit_once('.').map_or("", |(_, extension)| extension);
        let mut reasons = Vec::new();

        if contains(&self.rules.private_extensions, extension)
            || contains(&self.rules.private_names, name)
        {
            add_reason(
                &mut reasons,
                "private-key-material",
                "path or extension commonly stores private key material",
                self.rules.scores.private_path,
            );
        }
        if contains(&self.rules.secret_names, name)
            || self
                .rules
                .secret_path_components
                .iter()
                .any(|component| path_has_component(&path, component))
        {
            add_reason(
                &mut reasons,
                "secret-bearing-path",
                "path is conventionally used for secrets or credentials",
                self.rules.scores.secret_path,
            );
        }
        if self
            .rules
            .deployment_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
            || self
                .rules
                .deployment_path_components
                .iter()
                .any(|component| path_has_component(&path, component))
            || contains(&self.rules.deployment_extensions, extension)
            || contains(&self.rules.deployment_names, name)
        {
            add_reason(
                &mut reasons,
                "deployment-and-identity-config",
                "deployment or infrastructure configuration can change runtime trust",
                self.rules.scores.deployment,
            );
        }
        if contains(&self.rules.entrypoint_names, name)
            || self
                .rules
                .entrypoint_suffixes
                .iter()
                .any(|suffix| path.ends_with(suffix))
        {
            add_reason(
                &mut reasons,
                "runtime-entrypoint",
                "runtime entrypoints directly influence executed behavior",
                self.rules.scores.entrypoint,
            );
        }
        if contains(&self.rules.lockfile_names, name) {
            add_reason(
                &mut reasons,
                "dependency-lock",
                "dependency lockfiles determine resolved supply-chain inputs",
                self.rules.scores.lockfile,
            );
        }

        if file.likely_text {
            let lowercase = String::from_utf8_lossy(file.bytes).to_ascii_lowercase();
            if lowercase
                .lines()
                .any(|line| contains(&self.rules.private_key_markers, line.trim()))
            {
                add_reason(
                    &mut reasons,
                    "private-key-material",
                    "content contains a private-key envelope marker",
                    self.rules.scores.private_content,
                );
            }
            if lowercase.lines().any(|line| {
                let line = line.trim();
                let assignment = line.strip_prefix("export ").unwrap_or(line);
                self.rules
                    .credential_prefixes
                    .iter()
                    .any(|marker| assignment.starts_with(marker))
            }) {
                add_reason(
                    &mut reasons,
                    "credential-assignment",
                    "content contains a credential-like assignment",
                    self.rules.scores.credential_content,
                );
            }
        }

        let secret_path_hint = reasons.iter().any(|reason| {
            matches!(
                reason.rule_id.as_str(),
                "private-key-material" | "secret-bearing-path" | "credential-assignment"
            )
        });
        if secret_path_hint
            && (self.rules.entropy_min_bytes..=self.rules.entropy_max_bytes).contains(&file.size)
            && file.entropy_bits_per_byte >= self.rules.entropy_threshold
        {
            add_reason(
                &mut reasons,
                "high-entropy-secret-candidate",
                "secret-like file has high entropy consistent with encoded key material",
                self.rules.scores.high_entropy,
            );
        }

        reasons.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });
        reasons.dedup_by(|left, right| left.rule_id == right.rule_id);
        let strongest = reasons
            .first()
            .map_or(self.rules.scores.default, |reason| reason.score);
        let corroborating = reasons
            .len()
            .saturating_sub(1)
            .min(self.rules.max_corroborating_rules) as u8;
        let confidence = strongest
            .saturating_add(corroborating.saturating_mul(self.rules.corroboration_bonus))
            .min(self.rules.confidence_cap);
        let criticality = if confidence >= self.rules.critical_threshold {
            Criticality::Critical
        } else if confidence >= self.rules.important_threshold {
            Criticality::Important
        } else {
            Criticality::Standard
        };
        if reasons.is_empty() {
            reasons.push(ClassificationReason {
                rule_id: "default-standard".to_owned(),
                detail: "no critical path or content rule matched".to_owned(),
                score: self.rules.scores.default,
            });
        }

        vec![ClassificationSuggestion {
            path: file.relative_path.to_owned(),
            criticality,
            confidence,
            entropy_bits_per_byte: file.entropy_bits_per_byte,
            reasons,
        }]
    }
}

fn validate_rule_document(rules: &RuleDocument) -> Result<(), ClassifierError> {
    if rules.version != RULE_SET_VERSION
        || rules.private_extensions.is_empty()
        || rules.private_key_markers.is_empty()
        || !rules.entropy_threshold.is_finite()
        || !(0.0..=8.0).contains(&rules.entropy_threshold)
        || rules.entropy_min_bytes == 0
        || rules.entropy_min_bytes > rules.entropy_max_bytes
        || rules.important_threshold == 0
        || rules.important_threshold >= rules.critical_threshold
        || rules.critical_threshold > rules.confidence_cap
        || rules.confidence_cap > 100
        || rules.max_corroborating_rules > 16
    {
        return Err(ClassifierError::InvalidRuleDocument(
            "rule version, thresholds, entropy bounds, or required lists are invalid".to_owned(),
        ));
    }
    for values in [
        &rules.private_extensions,
        &rules.private_names,
        &rules.secret_names,
        &rules.secret_path_components,
        &rules.deployment_prefixes,
        &rules.deployment_path_components,
        &rules.deployment_extensions,
        &rules.deployment_names,
        &rules.entrypoint_names,
        &rules.entrypoint_suffixes,
        &rules.lockfile_names,
        &rules.private_key_markers,
        &rules.credential_prefixes,
    ] {
        if values.iter().any(|value| value.is_empty())
            || values.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ClassifierError::InvalidRuleDocument(
                "rule lists must be non-empty, unique, and sorted".to_owned(),
            ));
        }
    }
    let scores = [
        rules.scores.private_path,
        rules.scores.secret_path,
        rules.scores.deployment,
        rules.scores.entrypoint,
        rules.scores.lockfile,
        rules.scores.private_content,
        rules.scores.credential_content,
        rules.scores.high_entropy,
        rules.scores.default,
    ];
    if scores.iter().any(|score| *score == 0 || *score > 100) {
        return Err(ClassifierError::InvalidRuleDocument(
            "rule scores must be between 1 and 100".to_owned(),
        ));
    }
    for monitoring in [
        &rules.monitoring.critical,
        &rules.monitoring.important,
        &rules.monitoring.standard,
    ] {
        if monitoring.mode.is_empty()
            || monitoring.mode.len() > 64
            || !monitoring
                .mode
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            || monitoring.fallback_secs < 60
        {
            return Err(ClassifierError::InvalidRuleDocument(
                "monitoring modes or fallback intervals are invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn contains(values: &[String], candidate: &str) -> bool {
    values
        .binary_search_by(|value| value.as_str().cmp(candidate))
        .is_ok()
}

fn path_has_component(path: &str, expected: &str) -> bool {
    path.split('/').any(|component| component == expected)
}

fn add_reason(reasons: &mut Vec<ClassificationReason>, rule_id: &str, detail: &str, score: u8) {
    reasons.push(ClassificationReason {
        rule_id: rule_id.to_owned(),
        detail: detail.to_owned(),
        score,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_scan_core::{ScanEngine, ScanOptions};

    #[test]
    fn classifies_private_keys_and_entrypoints_with_reasons() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("identity.pem"),
            b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        )
        .unwrap();
        std::fs::write(directory.path().join("main.rs"), b"fn main() {}").unwrap();
        std::fs::write(directory.path().join("notes.txt"), b"documentation").unwrap();
        let report = ScanEngine::new(directory.path(), ScanOptions::default())
            .unwrap()
            .scan(&ShieldClassifier::new().unwrap())
            .unwrap();
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.findings[0].path, "identity.pem");
        assert_eq!(report.findings[0].criticality, Criticality::Critical);
        assert_eq!(report.findings[1].criticality, Criticality::Important);
        assert_eq!(report.findings[2].criticality, Criticality::Standard);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.reasons.is_empty())
        );
    }

    #[test]
    fn rule_metadata_is_stable_and_versioned() {
        let classifier = ShieldClassifier::new().unwrap();
        let metadata = classifier.metadata();
        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.sha256.len(), 64);
        assert_eq!(metadata.update_mode, "signed-compiled-in");
        assert_eq!(metadata.signature_algorithm, "ML-DSA-65");
        assert!(verify_rule_signature(b"tampered rules").is_err());
    }

    #[test]
    fn output_groups_every_path_once_without_activating_policy() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".env"), b"TOKEN=value").unwrap();
        std::fs::write(directory.path().join("notes.txt"), b"notes").unwrap();
        let classifier = ShieldClassifier::new().unwrap();
        let scan = ScanEngine::new(directory.path(), ScanOptions::default())
            .unwrap()
            .scan(&classifier)
            .unwrap();
        let output = classifier.output(scan);
        assert_eq!(output.schema_version, 1);
        let paths: Vec<_> = output
            .monitoring_groups
            .iter()
            .flat_map(|group| group.paths.iter().map(String::as_str))
            .collect();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&".env"));
        assert!(paths.contains(&"notes.txt"));
    }

    #[test]
    fn source_code_containing_rule_literals_is_not_a_secret() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("rules.rs"),
            br#"const MARKERS: &[&str] = &["-----BEGIN PRIVATE KEY-----", "TOKEN="];"#,
        )
        .unwrap();
        let classifier = ShieldClassifier::new().unwrap();
        let report = ScanEngine::new(directory.path(), ScanOptions::default())
            .unwrap()
            .scan(&classifier)
            .unwrap();
        assert_eq!(report.findings[0].criticality, Criticality::Standard);
    }
}
