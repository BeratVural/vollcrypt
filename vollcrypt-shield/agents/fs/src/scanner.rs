use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use sha2::{Digest, Sha256};
use vollcrypt_shield_core::{
    DifferenceKind, EntryKind, IntegrityEntry, NormalizedPath, ResourceGovernor, Snapshot,
    SparseMerkleTree, VerificationDifference, VerificationReport,
};
use walkdir::WalkDir;

use crate::config::ScopeConfig;
use crate::error::{AgentError, Result};
use crate::metadata::CapturedMetadata;

const FILE_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-FILE-v1\0";
const DIRECTORY_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-DIRECTORY-v1\0";
const SYMLINK_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-SYMLINK-v1\0";

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub entries: Vec<IntegrityEntry>,
    pub root: [u8; 32],
}

pub struct Scanner {
    includes: GlobSet,
    excludes: GlobSet,
}

impl Scanner {
    pub fn new(scope: &ScopeConfig) -> Result<Self> {
        Ok(Self {
            includes: compile_globs(&scope.include)?,
            excludes: compile_globs(&scope.exclude)?,
        })
    }

    pub fn full_scan(&self, scope: &ScopeConfig) -> Result<ScanResult> {
        let mut governor = ResourceGovernor::new(scope.full_scan.clone());
        let mut entries = Vec::new();

        for item in WalkDir::new(&scope.root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
        {
            let item = item.map_err(|error| AgentError::Scan(error.to_string()))?;
            if item.path() == scope.root {
                continue;
            }
            let normalized = relative_normalized(&scope.root, item.path())?;
            if !self.matches(&normalized) {
                continue;
            }
            governor.before_item();
            entries.push(scan_entry(item.path(), normalized, scope)?);
            governor.after_item();
        }

        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let tree = SparseMerkleTree::from_entries(entries.iter().cloned())?;
        Ok(ScanResult {
            entries,
            root: tree.root(),
        })
    }

    pub fn incremental_scan(
        &self,
        scope: &ScopeConfig,
        paths: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Vec<IntegrityEntry>> {
        let paths: Vec<_> = paths.into_iter().collect();
        if paths.len() > scope.incremental_scan.max_incremental_paths {
            return Err(AgentError::Scan(format!(
                "incremental path count {} exceeds configured maximum {}",
                paths.len(),
                scope.incremental_scan.max_incremental_paths
            )));
        }
        let mut governor = ResourceGovernor::new(scope.incremental_scan.clone());
        let canonical_root = scope.root.canonicalize()?;
        let mut entries = Vec::new();
        for path in paths {
            let absolute = if path.is_absolute() {
                path
            } else {
                scope.root.join(path)
            };
            let parent = absolute.parent().ok_or_else(|| {
                AgentError::Scan(format!("path has no parent: {}", absolute.display()))
            })?;
            let canonical_parent = parent.canonicalize()?;
            if !canonical_parent.starts_with(&canonical_root) {
                return Err(AgentError::Scan(format!(
                    "incremental path escapes scope: {}",
                    absolute.display()
                )));
            }
            if !absolute.exists() && std::fs::symlink_metadata(&absolute).is_err() {
                continue;
            }
            let normalized = relative_normalized(&scope.root, &absolute)?;
            if !self.matches(&normalized) {
                continue;
            }
            governor.before_item();
            entries.push(scan_entry(&absolute, normalized, scope)?);
            governor.after_item();
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        entries.dedup_by(|left, right| left.path == right.path);
        Ok(entries)
    }

    pub fn incremental_update(
        &self,
        scope: &ScopeConfig,
        current: &mut SparseMerkleTree,
        paths: impl IntoIterator<Item = PathBuf>,
    ) -> Result<ScanResult> {
        let mut affected = std::collections::BTreeSet::new();
        let mut whole_scope = false;
        for path in paths {
            let absolute = if path.is_absolute() {
                path
            } else {
                scope.root.join(path)
            };
            if absolute == scope.root {
                whole_scope = true;
                continue;
            }
            affected.insert(relative_normalized(&scope.root, &absolute)?);
        }
        if affected.len() > scope.incremental_scan.max_incremental_paths {
            return Err(AgentError::Scan(format!(
                "incremental path count {} exceeds configured maximum {}",
                affected.len(),
                scope.incremental_scan.max_incremental_paths
            )));
        }

        let mut updated = current.clone();
        let stale: Vec<_> = updated
            .entries()
            .filter(|entry| {
                whole_scope
                    || affected
                        .iter()
                        .any(|path| is_same_or_descendant(&entry.path, path))
            })
            .map(|entry| entry.path.clone())
            .collect();
        for path in stale {
            updated.remove(&path);
        }

        let mut candidates = std::collections::BTreeSet::new();
        if whole_scope {
            collect_bounded_paths(
                &scope.root,
                &mut candidates,
                scope.incremental_scan.max_incremental_paths,
            )?;
            candidates.remove(&scope.root);
        }
        for path in &affected {
            let absolute = scope.root.join(path.as_str());
            let metadata = match std::fs::symlink_metadata(&absolute) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.is_dir() {
                collect_bounded_paths(
                    &absolute,
                    &mut candidates,
                    scope.incremental_scan.max_incremental_paths,
                )?;
            } else {
                candidates.insert(absolute);
            }
        }

        let mut governor = ResourceGovernor::new(scope.incremental_scan.clone());
        for path in candidates {
            let normalized = relative_normalized(&scope.root, &path)?;
            if !self.matches(&normalized) {
                continue;
            }
            governor.before_item();
            updated.upsert(scan_entry(&path, normalized, scope)?)?;
            governor.after_item();
        }
        let result = scan_result_from_tree(&updated);
        *current = updated;
        Ok(result)
    }

    pub fn compare(snapshot: &Snapshot, observed: &ScanResult) -> VerificationReport {
        let baseline: BTreeMap<_, _> = snapshot
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect();
        let current: BTreeMap<_, _> = observed
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect();
        let mut differences = Vec::new();

        for (path, expected) in &baseline {
            match current.get(path) {
                None => differences.push(VerificationDifference {
                    path: path.clone(),
                    kind: DifferenceKind::Removed,
                }),
                Some(actual) if *actual != *expected => {
                    differences.push(VerificationDifference {
                        path: path.clone(),
                        kind: DifferenceKind::Modified,
                    });
                }
                Some(_) => {}
            }
        }
        for path in current.keys() {
            if !baseline.contains_key(path) {
                differences.push(VerificationDifference {
                    path: path.clone(),
                    kind: DifferenceKind::Added,
                });
            }
        }
        differences.sort_by(|left, right| left.path.cmp(&right.path));
        VerificationReport {
            scope_id: snapshot.scope_id.clone(),
            baseline_root: snapshot.root,
            observed_root: observed.root,
            differences,
        }
    }

    fn matches(&self, path: &NormalizedPath) -> bool {
        let included = self.includes.is_empty() || self.includes.is_match(path.as_str());
        included && !self.excludes.is_match(path.as_str())
    }
}

fn collect_bounded_paths(
    root: &Path,
    candidates: &mut std::collections::BTreeSet<PathBuf>,
    maximum: usize,
) -> Result<()> {
    for item in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        candidates.insert(
            item.map_err(|error| AgentError::Scan(error.to_string()))?
                .into_path(),
        );
        if candidates.len() > maximum {
            return Err(AgentError::Scan(format!(
                "incremental expansion exceeds configured maximum {maximum}"
            )));
        }
    }
    Ok(())
}

fn is_same_or_descendant(path: &NormalizedPath, parent: &NormalizedPath) -> bool {
    path == parent
        || path
            .as_str()
            .strip_prefix(parent.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn scan_result_from_tree(tree: &SparseMerkleTree) -> ScanResult {
    let mut entries: Vec<_> = tree.entries().cloned().collect();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    ScanResult {
        entries,
        root: tree.root(),
    }
}

fn compile_globs(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern)
                .map_err(|error| AgentError::Config(format!("invalid glob {pattern}: {error}")))?,
        );
    }
    builder
        .build()
        .map_err(|error| AgentError::Config(error.to_string()))
}

fn relative_normalized(root: &Path, path: &Path) -> Result<NormalizedPath> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| AgentError::Scan(format!("path escapes scope: {}", path.display())))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().ok_or_else(|| {
                    AgentError::Scan(format!(
                        "non-UTF-8 path is unsupported by protocol v1: {}",
                        path.display()
                    ))
                })?;
                parts.push(value);
            }
            _ => {
                return Err(AgentError::Scan(format!(
                    "non-canonical path component: {}",
                    path.display()
                )));
            }
        }
    }
    NormalizedPath::new(parts.join("/")).map_err(Into::into)
}

fn scan_entry(
    path: &Path,
    normalized: NormalizedPath,
    scope: &ScopeConfig,
) -> Result<IntegrityEntry> {
    let metadata = std::fs::symlink_metadata(path)?;
    let captured = CapturedMetadata::capture(path, &scope.metadata)?;
    let metadata_digest = captured.digest()?;

    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path)?;
        let target = target.to_str().ok_or_else(|| {
            AgentError::Scan(format!("non-UTF-8 symlink target: {}", path.display()))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(SYMLINK_DOMAIN);
        hasher.update((target.len() as u64).to_be_bytes());
        hasher.update(target.as_bytes());
        return Ok(IntegrityEntry::new(
            normalized,
            EntryKind::Symlink,
            hasher.finalize().into(),
            metadata_digest,
            target.len() as u64,
        ));
    }

    if metadata.is_dir() {
        return Ok(IntegrityEntry::new(
            normalized,
            EntryKind::Directory,
            Sha256::digest(DIRECTORY_DOMAIN).into(),
            metadata_digest,
            0,
        ));
    }

    if !metadata.is_file() {
        return Err(AgentError::Scan(format!(
            "unsupported filesystem entry: {}",
            path.display()
        )));
    }

    let file = File::open(path)?;
    let before = file.metadata()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    hasher.update(FILE_DOMAIN);
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let after = reader.get_ref().metadata()?;
    if metadata_changed_during_read(&before, &after) {
        return Err(AgentError::Scan(format!(
            "file changed while being hashed: {}",
            path.display()
        )));
    }

    Ok(IntegrityEntry::new(
        normalized,
        EntryKind::File,
        hasher.finalize().into(),
        metadata_digest,
        after.len(),
    ))
}

fn metadata_changed_during_read(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
    }
    #[cfg(not(unix))]
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use vollcrypt_shield_core::{MetadataPolicy, ResponsePolicy, ScanProfile};

    fn scope(root: PathBuf) -> ScopeConfig {
        ScopeConfig {
            id: "test".to_owned(),
            root,
            include: vec!["**".to_owned()],
            exclude: vec![],
            metadata: MetadataPolicy::default(),
            full_scan: ScanProfile::full_default(),
            incremental_scan: ScanProfile::incremental_default(),
            full_rescan_interval_secs: 300,
            response: ResponsePolicy::default(),
        }
    }

    #[test]
    fn scan_detects_content_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"one")
            .unwrap();
        let scope = scope(dir.path().to_path_buf());
        let scanner = Scanner::new(&scope).unwrap();
        let first = scanner.full_scan(&scope).unwrap();
        std::fs::write(&path, b"two").unwrap();
        let second = scanner.full_scan(&scope).unwrap();
        assert_ne!(first.root, second.root);
    }

    #[test]
    fn comparison_reports_added_removed_and_modified() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"a").unwrap();
        std::fs::write(dir.path().join("b"), b"b").unwrap();
        let scope = scope(dir.path().to_path_buf());
        let scanner = Scanner::new(&scope).unwrap();
        let first = scanner.full_scan(&scope).unwrap();
        let baseline = Snapshot::new("test", first.entries.clone(), 1).unwrap();
        std::fs::write(dir.path().join("a"), b"changed").unwrap();
        std::fs::remove_file(dir.path().join("b")).unwrap();
        std::fs::write(dir.path().join("c"), b"c").unwrap();
        let report = Scanner::compare(&baseline, &scanner.full_scan(&scope).unwrap());
        assert_eq!(report.differences.len(), 3);
    }

    #[test]
    fn incremental_update_removes_deleted_subtree_and_adds_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("old"), b"old").unwrap();
        let scope = scope(dir.path().to_path_buf());
        let scanner = Scanner::new(&scope).unwrap();
        let initial = scanner.full_scan(&scope).unwrap();
        let mut tree = SparseMerkleTree::from_entries(initial.entries).unwrap();

        std::fs::remove_dir_all(&nested).unwrap();
        std::fs::write(dir.path().join("new"), b"new").unwrap();
        scanner
            .incremental_update(&scope, &mut tree, [nested.clone(), dir.path().join("new")])
            .unwrap();
        let incremental = scan_result_from_tree(&tree);
        let full = scanner.full_scan(&scope).unwrap();
        assert_eq!(incremental.root, full.root);
        assert_eq!(incremental.entries, full.entries);
    }
}
