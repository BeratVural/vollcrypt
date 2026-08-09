#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("walk error: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("invalid scan configuration: {0}")]
    Config(String),
    #[error("scan limit exceeded: {0}")]
    Limit(String),
}

pub type Result<T> = std::result::Result<T, ScanError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_file_bytes: 1_048_576,
            max_total_bytes: 268_435_456,
        }
    }
}

impl ScanLimits {
    fn validate(&self) -> Result<()> {
        if self.max_files == 0
            || self.max_file_bytes == 0
            || self.max_total_bytes < self.max_file_bytes
            || usize::try_from(self.max_file_bytes).is_err()
        {
            return Err(ScanError::Config(
                "scan limits must be non-zero and total bytes must cover one file".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    pub limits: ScanLimits,
    pub excluded_directories: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            limits: ScanLimits::default(),
            excluded_directories: vec![
                ".git".to_owned(),
                ".hg".to_owned(),
                ".svn".to_owned(),
                "node_modules".to_owned(),
                "target".to_owned(),
                "vendor".to_owned(),
            ],
        }
    }
}

pub struct ScannedFile<'content> {
    pub relative_path: &'content str,
    pub size: u64,
    pub bytes: &'content [u8],
    pub entropy_bits_per_byte: f64,
    pub likely_text: bool,
}

pub trait RuleSet {
    type Finding;

    fn analyze(&self, file: &ScannedFile<'_>) -> Vec<Self::Finding>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport<Finding> {
    pub root: String,
    pub files_analyzed: usize,
    pub bytes_analyzed: u64,
    pub symlinks_skipped: usize,
    pub oversized_files_skipped: usize,
    pub findings: Vec<Finding>,
}

pub struct ScanEngine {
    root: PathBuf,
    options: ScanOptions,
}

impl ScanEngine {
    pub fn new(root: &Path, mut options: ScanOptions) -> Result<Self> {
        options.limits.validate()?;
        options.excluded_directories.sort();
        options.excluded_directories.dedup();
        if options.excluded_directories.iter().any(|name| {
            name.is_empty()
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\\')
        }) {
            return Err(ScanError::Config(
                "excluded directories must be single path components".to_owned(),
            ));
        }
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(ScanError::Config(
                "scan root must be a directory".to_owned(),
            ));
        }
        Ok(Self { root, options })
    }

    pub fn scan<Rules: RuleSet>(&self, rules: &Rules) -> Result<ScanReport<Rules::Finding>> {
        let mut files_analyzed = 0_usize;
        let mut files_considered = 0_usize;
        let mut bytes_analyzed = 0_u64;
        let mut symlinks_skipped = 0_usize;
        let mut oversized_files_skipped = 0_usize;
        let mut findings = Vec::new();

        let walker = WalkDir::new(&self.root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| self.should_descend(entry));
        for entry in walker {
            let entry = entry?;
            let file_type = entry.file_type();
            if file_type.is_symlink() {
                symlinks_skipped = symlinks_skipped.saturating_add(1);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            files_considered = files_considered.saturating_add(1);
            if files_considered > self.options.limits.max_files {
                return Err(ScanError::Limit(format!(
                    "file count exceeds {}",
                    self.options.limits.max_files
                )));
            }
            let canonical = entry.path().canonicalize()?;
            if !canonical.starts_with(&self.root) {
                return Err(ScanError::Config(
                    "scan entry resolves outside the configured root".to_owned(),
                ));
            }
            let metadata = std::fs::metadata(&canonical)?;
            if metadata.len() > self.options.limits.max_file_bytes {
                oversized_files_skipped = oversized_files_skipped.saturating_add(1);
                continue;
            }
            let next_total = bytes_analyzed
                .checked_add(metadata.len())
                .ok_or_else(|| ScanError::Limit("total byte count overflow".to_owned()))?;
            if next_total > self.options.limits.max_total_bytes {
                return Err(ScanError::Limit(format!(
                    "total bytes exceed {}",
                    self.options.limits.max_total_bytes
                )));
            }
            let capacity = usize::try_from(metadata.len())
                .map_err(|_| ScanError::Limit("file size exceeds address space".to_owned()))?;
            let mut bytes = Vec::with_capacity(capacity);
            File::open(&canonical)?
                .take(self.options.limits.max_file_bytes.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > self.options.limits.max_file_bytes {
                oversized_files_skipped = oversized_files_skipped.saturating_add(1);
                continue;
            }
            let relative_path = normalized_relative_path(&self.root, &canonical)?;
            let entropy_bits_per_byte = shannon_entropy(&bytes);
            let likely_text = is_likely_text(&bytes);
            findings.extend(rules.analyze(&ScannedFile {
                relative_path: &relative_path,
                size: bytes.len() as u64,
                bytes: &bytes,
                entropy_bits_per_byte,
                likely_text,
            }));
            files_analyzed += 1;
            bytes_analyzed = bytes_analyzed.saturating_add(bytes.len() as u64);
        }

        Ok(ScanReport {
            root: self.root.display().to_string(),
            files_analyzed,
            bytes_analyzed,
            symlinks_skipped,
            oversized_files_skipped,
            findings,
        })
    }

    fn should_descend(&self, entry: &DirEntry) -> bool {
        entry.depth() == 0
            || !entry.file_type().is_dir()
            || self
                .options
                .excluded_directories
                .binary_search(&entry.file_name().to_string_lossy().into_owned())
                .is_err()
    }
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count != 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn is_likely_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let suspicious = bytes
        .iter()
        .filter(|byte| **byte == 0 || (**byte < 0x09) || (0x0e..0x20).contains(&**byte))
        .count();
    suspicious.saturating_mul(100) <= bytes.len()
}

fn normalized_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ScanError::Config("scan path escaped root".to_owned()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let value = component.as_os_str().to_str().ok_or_else(|| {
            ScanError::Config("non-UTF-8 paths are not supported by analysis output".to_owned())
        })?;
        if value.is_empty() || value == "." || value == ".." {
            return Err(ScanError::Config("ambiguous relative path".to_owned()));
        }
        parts.push(value);
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Paths;

    impl RuleSet for Paths {
        type Finding = String;

        fn analyze(&self, file: &ScannedFile<'_>) -> Vec<Self::Finding> {
            vec![file.relative_path.to_owned()]
        }
    }

    #[test]
    fn scan_is_deterministic_bounded_and_excludes_dependency_trees() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("b.txt"), b"bbb").unwrap();
        std::fs::write(directory.path().join("a.txt"), b"aaa").unwrap();
        std::fs::create_dir(directory.path().join("node_modules")).unwrap();
        std::fs::write(directory.path().join("node_modules/ignored.js"), b"ignored").unwrap();
        std::fs::write(directory.path().join("large.bin"), [0_u8; 32]).unwrap();
        let engine = ScanEngine::new(
            directory.path(),
            ScanOptions {
                limits: ScanLimits {
                    max_file_bytes: 16,
                    max_total_bytes: 64,
                    ..ScanLimits::default()
                },
                ..ScanOptions::default()
            },
        )
        .unwrap();
        let report = engine.scan(&Paths).unwrap();
        assert_eq!(report.findings, vec!["a.txt", "b.txt"]);
        assert_eq!(report.oversized_files_skipped, 1);
    }

    #[test]
    fn entropy_distinguishes_constant_and_distributed_bytes() {
        assert_eq!(shannon_entropy(&[7; 64]), 0.0);
        let distributed: Vec<u8> = (0_u8..=255).collect();
        assert!((shannon_entropy(&distributed) - 8.0).abs() < f64::EPSILON);
    }
}
