#![no_main]
use libfuzzer_sys::fuzz_target;
use vollcrypt_files_core::WrapEntry;

fuzz_target!(|data: &[u8]| {
    let _ = WrapEntry::parse(data);
});
