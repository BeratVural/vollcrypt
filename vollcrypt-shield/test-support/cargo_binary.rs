use std::path::{Path, PathBuf};

pub fn resolve(cargo_executable: &str, binary_name: &str) -> PathBuf {
    let current_test = std::env::current_exe()
        .unwrap_or_else(|error| panic!("failed to resolve current test executable: {error}"));
    resolve_from(Path::new(cargo_executable), &current_test, binary_name)
}

pub fn resolve_from(cargo_executable: &Path, current_test: &Path, binary_name: &str) -> PathBuf {
    let profile_directory = current_test
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("test executable has no Cargo profile directory"));
    let profile_executable =
        profile_directory.join(format!("{binary_name}{}", std::env::consts::EXE_SUFFIX));
    if profile_executable.is_file() {
        return profile_executable;
    }
    if cargo_executable.is_file() {
        return cargo_executable.to_path_buf();
    }

    panic!(
        "{binary_name} was not found at {} or {}",
        profile_executable.display(),
        cargo_executable.display()
    );
}
