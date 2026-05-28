#![no_main]
use libfuzzer_sys::fuzz_target;
use vollcrypt_files_core::Header;

fuzz_target!(|data: &[u8]| {
    let _ = Header::parse(data);
});
