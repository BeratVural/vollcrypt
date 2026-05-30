use crate::error::FileFormatError;
use crate::header::{Header, SignedMetadata};
use crate::hybrid_sig::HybridPublicKey;
use crate::keylog::{KeyLog, KeyLogEntryType};
use crate::signature::{
    extract_key_log_id_plain, extract_key_log_id_sealed, verify_header_signature_plain,
    verify_header_signature_sealed, VerificationPolicy,
};
use subtle::ConstantTimeEq;

pub struct SenderInfo {
    pub signer_pubkey: HybridPublicKey,
    pub user_id: [u8; 16],
    pub device_id: [u8; 16],
    pub device_was_active: bool,
    pub human_label: Option<String>,
}

pub fn resolve_sender(
    header: &Header,
    key_log: &KeyLog,
    sealed_gk: Option<&[u8; 32]>,
    policy: VerificationPolicy,
) -> Result<SenderInfo, FileFormatError> {
    let signed_metadata = header
        .signed_metadata
        .as_ref()
        .ok_or(FileFormatError::HeaderNotSigned)?;

    let (signer_pubkey, key_log_id, timestamp) = match signed_metadata {
        SignedMetadata::Plain { timestamp, .. } => {
            let pk = verify_header_signature_plain(header, policy)?;
            let kl_id = extract_key_log_id_plain(header)?;
            (pk, kl_id, *timestamp)
        }
        SignedMetadata::Sealed { timestamp, .. } => {
            let gk = sealed_gk.ok_or(FileFormatError::SealedGkRequired)?;
            let pk = verify_header_signature_sealed(header, gk, key_log, policy)?;
            let kl_id = extract_key_log_id_sealed(header, gk)?;
            (pk, kl_id, *timestamp)
        }
    };

    let entry = key_log
        .lookup_by_entry_hash(&key_log_id)
        .ok_or(FileFormatError::KeyLogEntryNotFound)?;

    if let KeyLogEntryType::DeviceRegister {
        device_id,
        user_id,
        device_pubkey,
        human_label,
    } = &entry.entry
    {
        if !bool::from(signer_pubkey.ct_eq(device_pubkey)) {
            return Err(FileFormatError::SignatureInvalid);
        }

        let device_was_active = key_log.device_was_active_at(device_id, timestamp);

        Ok(SenderInfo {
            signer_pubkey,
            user_id: *user_id,
            device_id: *device_id,
            device_was_active,
            human_label: Some(human_label.clone()),
        })
    } else {
        Err(FileFormatError::KeyLogEntryNotFound)
    }
}
