#![no_main]
use libfuzzer_sys::fuzz_target;
use vollcrypt_files_core::GroupManifest;

fuzz_target!(|data: &[u8]| {
    let _ = GroupManifest::parse(data);
});
