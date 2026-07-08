use std::fs::{self, File};
use std::io::{Read, Write, Seek};
use std::path::{Path, PathBuf};
use crate::error::FileFormatError;
use crate::aead::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use sha2::Sha256;
use hkdf::Hkdf;
use rand::RngCore;

const VDA_MAGIC: &[u8; 4] = b"VDA\x01";

/// Derives a unique file encryption key from the folder master key and the relative path of the file.
pub fn derive_file_key(dek: &[u8; 32], relative_path: &str) -> Result<[u8; 32], FileFormatError> {
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut file_key = [0u8; 32];
    hk.expand(relative_path.as_bytes(), &mut file_key)
        .map_err(|_| FileFormatError::IntegrityError("HKDF expansion failed for file key".to_string()))?;
    Ok(file_key)
}

fn generate_iv() -> [u8; 12] {
    let mut iv = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    iv
}

fn collect_entries(dir: &Path, base_dir: &Path, entries: &mut Vec<(PathBuf, String, bool)>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        let rel_path = path.strip_prefix(base_dir)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let rel_path_str = rel_path.to_string_lossy().replace('\\', "/");
        
        let is_dir = path.is_dir();
        entries.push((path.clone(), rel_path_str, is_dir));
        
        if is_dir {
            collect_entries(&path, base_dir, entries)?;
        }
    }
    Ok(())
}

/// Packs a directory recursively into a single VDA archive.
/// Individual files are encrypted with derived keys.
pub fn pack_directory(
    src_dir: &Path,
    archive_path: &Path,
    dek: &[u8; 32],
) -> Result<(), FileFormatError> {
    let mut entries = Vec::new();
    collect_entries(src_dir, src_dir, &mut entries)
        .map_err(|e| FileFormatError::IoError(format!("Failed to walk directory: {}", e)))?;
        
    let mut archive_file = File::create(archive_path)
        .map_err(|e| FileFormatError::IoError(format!("Failed to create archive file: {}", e)))?;
        
    // 1. Write Magic
    archive_file.write_all(VDA_MAGIC)
        .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        
    // 2. Write Entry Count
    let entry_count = entries.len() as u32;
    archive_file.write_all(&entry_count.to_be_bytes())
        .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        
    // 3. Process and Write each entry
    for (abs_path, rel_path, is_dir) in entries {
        let rel_path_bytes = rel_path.as_bytes();
        let path_len = rel_path_bytes.len() as u32;
        
        // Write path length
        archive_file.write_all(&path_len.to_be_bytes())
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        // Write relative path
        archive_file.write_all(rel_path_bytes)
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        // Write is_dir
        archive_file.write_all(&[if is_dir { 1 } else { 0 }])
            .map_err(|e| FileFormatError::IoError(e.to_string()))?;
            
        if !is_dir {
            // Read file plaintext
            let plaintext = fs::read(&abs_path)
                .map_err(|e| FileFormatError::IoError(format!("Failed to read file {:?}: {}", abs_path, e)))?;
                
            let plaintext_len = plaintext.len() as u64;
            
            // Generate IV
            let iv = generate_iv();
            
            // Derive unique key for this file
            let file_key = derive_file_key(dek, &rel_path)?;
            
            // Encrypt content
            let (ciphertext, tag) = aes256_gcm_encrypt(&file_key, &iv, &[], &plaintext)?;
            
            // Write plaintext size
            archive_file.write_all(&plaintext_len.to_be_bytes())
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;
            // Write IV
            archive_file.write_all(&iv)
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;
            // Write tag
            archive_file.write_all(&tag)
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;
            // Write ciphertext
            archive_file.write_all(&ciphertext)
                .map_err(|e| FileFormatError::IoError(e.to_string()))?;
        }
    }
    
    Ok(())
}

/// Unpacks a VDA archive into a destination directory.
/// Individual files are decrypted with derived keys.
pub fn unpack_directory(
    archive_path: &Path,
    dest_dir: &Path,
    dek: &[u8; 32],
) -> Result<(), FileFormatError> {
    let mut archive_file = File::open(archive_path)
        .map_err(|e| FileFormatError::IoError(format!("Failed to open archive file: {}", e)))?;
        
    // 1. Read and verify Magic
    let mut magic = [0u8; 4];
    archive_file.read_exact(&mut magic)
        .map_err(|e| FileFormatError::IoError(format!("Failed to read magic: {}", e)))?;
    if &magic != VDA_MAGIC {
        return Err(FileFormatError::InvalidMagic);
    }
    
    // 2. Read Entry Count
    let mut count_bytes = [0u8; 4];
    archive_file.read_exact(&mut count_bytes)
        .map_err(|e| FileFormatError::IoError(format!("Failed to read entry count: {}", e)))?;
    let entry_count = u32::from_be_bytes(count_bytes);
    
    // Create base destination directory
    fs::create_dir_all(dest_dir)
        .map_err(|e| FileFormatError::IoError(format!("Failed to create destination directory: {}", e)))?;
        
    // 3. Parse and extract each entry
    for _ in 0..entry_count {
        // Read path length
        let mut path_len_bytes = [0u8; 4];
        archive_file.read_exact(&mut path_len_bytes)
            .map_err(|e| FileFormatError::IoError(format!("Failed to read path length: {}", e)))?;
        let path_len = u32::from_be_bytes(path_len_bytes) as usize;
        
        // Read relative path
        let mut path_bytes = vec![0u8; path_len];
        archive_file.read_exact(&mut path_bytes)
            .map_err(|e| FileFormatError::IoError(format!("Failed to read relative path: {}", e)))?;
        let rel_path = String::from_utf8(path_bytes)
            .map_err(|e| FileFormatError::IoError(format!("Invalid UTF-8 path: {}", e)))?;
            
        // Read is_dir
        let mut is_dir_byte = [0u8; 1];
        archive_file.read_exact(&mut is_dir_byte)
            .map_err(|e| FileFormatError::IoError(format!("Failed to read is_dir: {}", e)))?;
        let is_dir = is_dir_byte[0] == 1;
        
        let path_obj = std::path::Path::new(&rel_path);
        if path_obj.is_absolute() {
            return Err(FileFormatError::IoError(format!("Absolute path not allowed in archive: {}", rel_path)));
        }
        for component in path_obj.components() {
            match component {
                std::path::Component::ParentDir => {
                    return Err(FileFormatError::IoError(format!("Path traversal attempt detected: {}", rel_path)));
                }
                std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                    return Err(FileFormatError::IoError(format!("Invalid path component in archive: {}", rel_path)));
                }
                _ => {}
            }
        }
        let target_path = dest_dir.join(&rel_path);
        
        if is_dir {
            fs::create_dir_all(&target_path)
                .map_err(|e| FileFormatError::IoError(format!("Failed to create directory {:?}: {}", target_path, e)))?;
        } else {
            // Read plaintext/ciphertext size
            let mut size_bytes = [0u8; 8];
            archive_file.read_exact(&mut size_bytes)
                .map_err(|e| FileFormatError::IoError(format!("Failed to read file size: {}", e)))?;
            let size = u64::from_be_bytes(size_bytes) as usize;
            
            // Read IV
            let mut iv = [0u8; 12];
            archive_file.read_exact(&mut iv)
                .map_err(|e| FileFormatError::IoError(format!("Failed to read IV: {}", e)))?;
                
            // Read tag
            let mut tag = [0u8; 16];
            archive_file.read_exact(&mut tag)
                .map_err(|e| FileFormatError::IoError(format!("Failed to read tag: {}", e)))?;
                
            // Read ciphertext
            let file_len = archive_file.metadata().map(|m| m.len()).unwrap_or(0);
            let current_pos = archive_file.stream_position().map_err(|e| FileFormatError::IoError(e.to_string()))?;
            let remaining_bytes = file_len.saturating_sub(current_pos);
            if size as u64 > remaining_bytes {
                return Err(FileFormatError::IoError("Archive file is truncated or has invalid size".to_string()));
            }
            let mut ciphertext = vec![0u8; size];
            archive_file.read_exact(&mut ciphertext)
                .map_err(|e| FileFormatError::IoError(format!("Failed to read ciphertext: {}", e)))?;
                
            // Derive unique file key
            let file_key = derive_file_key(dek, &rel_path)?;
            
            // Decrypt content
            let plaintext = aes256_gcm_decrypt(&file_key, &iv, &[], &ciphertext, &tag)?;
            
            // Ensure parent directory exists
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| FileFormatError::IoError(format!("Failed to create parent directory {:?}: {}", parent, e)))?;
            }
            
            // Write plaintext to target path
            fs::write(&target_path, plaintext)
                .map_err(|e| FileFormatError::IoError(format!("Failed to write file {:?}: {}", target_path, e)))?;
        }
    }
    
    Ok(())
}

/// Checks if a file is a VDA archive by reading its magic bytes.
pub fn is_vda_archive(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_ok() {
            return &magic == VDA_MAGIC;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_pack_unpack_directory() {
        let dir = tempdir().unwrap();
        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        
        let sub_dir = src_dir.join("sub");
        fs::create_dir(&sub_dir).unwrap();
        
        let file1 = src_dir.join("file1.txt");
        fs::write(&file1, b"Hello world!").unwrap();
        
        let file2 = sub_dir.join("file2.txt");
        fs::write(&file2, b"DeepMind pair programming").unwrap();
        
        let empty_dir = src_dir.join("empty_folder");
        fs::create_dir(&empty_dir).unwrap();
        
        let archive_path = dir.path().join("archive.vda");
        let dek = [42u8; 32];
        
        pack_directory(&src_dir, &archive_path, &dek).unwrap();
        
        assert!(is_vda_archive(&archive_path));
        
        let dest_dir = dir.path().join("dest");
        unpack_directory(&archive_path, &dest_dir, &dek).unwrap();
        
        assert_eq!(fs::read_to_string(dest_dir.join("file1.txt")).unwrap(), "Hello world!");
        assert_eq!(fs::read_to_string(dest_dir.join("sub/file2.txt")).unwrap(), "DeepMind pair programming");
        assert!(dest_dir.join("empty_folder").is_dir());
    }
}
