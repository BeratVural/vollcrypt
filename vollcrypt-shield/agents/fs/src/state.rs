use std::path::{Path, PathBuf};

use minicbor::{Decode, Encode};
use vollcrypt_shield_core::{FORMAT_VERSION, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};

use crate::error::{AgentError, Result};

const STATE_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Agent State v1";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct ContainmentState {
    #[n(0)]
    pub scope_id: String,
    #[n(1)]
    pub reason: String,
    #[n(2)]
    pub contained_at_unix_ms: u64,
    #[n(3)]
    pub last_reminder_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct StateDocument {
    #[n(0)]
    version: u16,
    #[n(1)]
    contained_scopes: Vec<ContainmentState>,
    #[n(2)]
    used_break_glass_nonces: Vec<[u8; 32]>,
}

impl Default for StateDocument {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            contained_scopes: Vec::new(),
            used_break_glass_nonces: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct SignedState {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

#[derive(Debug)]
pub struct StateStore {
    path: PathBuf,
    document: StateDocument,
}

impl StateStore {
    pub fn load_or_new(path: impl Into<PathBuf>, trusted_key: &MlDsa65PublicKey) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self {
                path,
                document: StateDocument::default(),
            });
        }
        let bytes = std::fs::read(&path)?;
        let signed: SignedState = decode_exact(&bytes)?;
        let embedded_key = MlDsa65PublicKey::from_bytes(&signed.public_key)?;
        if embedded_key.key_id() != trusted_key.key_id() {
            return Err(AgentError::Config(
                "state signer does not match configured agent key".to_owned(),
            ));
        }
        let signature = MlDsa65Signature::from_bytes(&signed.signature)?;
        trusted_key.verify_with_context(&signed.payload, STATE_SIGNATURE_CONTEXT, &signature)?;
        let document: StateDocument = decode_exact(&signed.payload)?;
        if document.version != FORMAT_VERSION {
            return Err(
                vollcrypt_shield_core::ShieldError::UnsupportedVersion(document.version).into(),
            );
        }
        Ok(Self { path, document })
    }

    pub fn is_contained(&self, scope_id: &str) -> bool {
        self.document
            .contained_scopes
            .iter()
            .any(|state| state.scope_id == scope_id)
    }

    pub fn containment(&self, scope_id: &str) -> Option<&ContainmentState> {
        self.document
            .contained_scopes
            .iter()
            .find(|state| state.scope_id == scope_id)
    }

    pub fn contain_scope(&mut self, scope_id: &str, reason: impl Into<String>, now_unix_ms: u64) {
        if self.is_contained(scope_id) {
            return;
        }
        self.document.contained_scopes.push(ContainmentState {
            scope_id: scope_id.to_owned(),
            reason: reason.into(),
            contained_at_unix_ms: now_unix_ms,
            last_reminder_unix_ms: now_unix_ms,
        });
        self.document
            .contained_scopes
            .sort_by(|left, right| left.scope_id.cmp(&right.scope_id));
    }

    pub fn release_scope(&mut self, scope_id: &str, nonce: [u8; 32]) -> Result<()> {
        if self
            .document
            .used_break_glass_nonces
            .binary_search(&nonce)
            .is_ok()
        {
            return Err(AgentError::BreakGlassReplay);
        }
        self.document
            .contained_scopes
            .retain(|state| state.scope_id != scope_id);
        self.document.used_break_glass_nonces.push(nonce);
        self.document.used_break_glass_nonces.sort();
        Ok(())
    }

    pub fn due_reminders(
        &mut self,
        now_unix_ms: u64,
        interval_secs: impl Fn(&str) -> u64,
    ) -> Vec<ContainmentState> {
        let mut due = Vec::new();
        for state in &mut self.document.contained_scopes {
            let interval_ms = interval_secs(&state.scope_id).saturating_mul(1_000);
            if now_unix_ms.saturating_sub(state.last_reminder_unix_ms) >= interval_ms {
                state.last_reminder_unix_ms = now_unix_ms;
                due.push(state.clone());
            }
        }
        due
    }

    pub fn save(&self, secret: &MlDsa65SecretKey) -> Result<()> {
        let payload = minicbor::to_vec(&self.document)
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        let public = secret.public_key()?;
        let signature = secret.sign_with_context(&payload, STATE_SIGNATURE_CONTEXT)?;
        let signed = SignedState {
            payload,
            public_key: public.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        };
        let encoded = minicbor::to_vec(signed)
            .map_err(|error| AgentError::Serialization(error.to_string()))?;
        write_atomic(&self.path, &encoded)
    }
}

fn decode_exact<'a, T>(bytes: &'a [u8]) -> Result<T>
where
    T: Decode<'a, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder
        .decode::<T>()
        .map_err(|error| AgentError::Serialization(error.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(AgentError::Serialization(
            "trailing bytes after state record".to_owned(),
        ));
    }
    Ok(value)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    match std::fs::rename(&temporary, path) {
        Ok(()) => {}
        Err(_error) if path.exists() => {
            let backup = path.with_extension("previous");
            if backup.exists() {
                std::fs::remove_file(&backup)?;
            }
            std::fs::rename(path, &backup)?;
            if let Err(replace_error) = std::fs::rename(&temporary, path) {
                let _ = std::fs::rename(&backup, path);
                return Err(replace_error.into());
            }
            std::fs::remove_file(backup)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_shield_core::MlDsa65KeyPair;

    #[test]
    fn containment_is_scope_local_and_nonce_is_single_use() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.cbor");
        let mut state = StateStore::load_or_new(&path, &pair.public).unwrap();
        state.contain_scope("a", "change", 1);
        assert!(state.is_contained("a"));
        assert!(!state.is_contained("b"));
        state.release_scope("a", [7; 32]).unwrap();
        assert!(state.release_scope("a", [7; 32]).is_err());
        state.save(&pair.secret).unwrap();
        let loaded = StateStore::load_or_new(path, &pair.public).unwrap();
        assert!(!loaded.is_contained("a"));
    }

    #[test]
    fn containment_reminders_remain_due_until_release() {
        let pair = MlDsa65KeyPair::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut state =
            StateStore::load_or_new(dir.path().join("state.cbor"), &pair.public).unwrap();
        state.contain_scope("a", "change", 1_000);
        assert!(state.due_reminders(60_999, |_| 60).is_empty());
        assert_eq!(state.due_reminders(61_000, |_| 60).len(), 1);
        assert!(state.due_reminders(61_001, |_| 60).is_empty());
        assert_eq!(state.due_reminders(121_000, |_| 60).len(), 1);
    }
}
