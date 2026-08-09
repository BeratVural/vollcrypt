use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use minicbor::{Decode, Encode};
use serde::Serialize;
use vollcrypt_shield_core::{MlDsa65KeyPair, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};
use vollcrypt_shield_protocol::{
    PROTOCOL_VERSION,
    pairing::{
        PairingAuthenticator, PairingCode, PairingHello, PairingInvitation, PairingReceipt,
        PairingRole, PairingSession,
    },
    transport::{read_cbor_frame, write_cbor_frame},
    witness::{AttestationRequest, SignedWitnessStatement, WitnessLedger, WitnessLedgerState},
};

use crate::{Result, WitnessError};

const WITNESS_STATE_CONTEXT: &[u8] = b"Vollcrypt Shield Witness State v1";

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
struct StateDocument {
    #[n(0)]
    version: u16,
    #[n(1)]
    witness_id: String,
    #[n(2)]
    trusted_agent_key_ids: Vec<[u8; 32]>,
    #[n(3)]
    ledger: WitnessLedgerState,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cbor(array)]
struct SignedState {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessStatus {
    pub witness_id: String,
    pub witness_key_id: String,
    pub trusted_agents: usize,
    pub tracked_scopes: usize,
}

pub struct WitnessNode {
    state_dir: PathBuf,
    witness_id: String,
    secret: MlDsa65SecretKey,
    public: MlDsa65PublicKey,
    trusted_agent_key_ids: Vec<[u8; 32]>,
    ledger: WitnessLedger,
}

impl WitnessNode {
    pub fn initialize(state_dir: &Path, witness_id: &str) -> Result<Self> {
        validate_state_dir(state_dir)?;
        validate_witness_id(witness_id)?;
        let keys = state_dir.join("keys");
        std::fs::create_dir_all(&keys)?;
        secure_directory(state_dir)?;
        secure_directory(&keys)?;
        let seed_path = keys.join("witness.seed");
        let public_path = keys.join("witness.public");
        let state_path = state_dir.join("state.cbor");
        if seed_path.exists() || public_path.exists() || state_path.exists() {
            return Err(WitnessError::Config(
                "refusing to overwrite existing witness state".to_owned(),
            ));
        }
        let pair = MlDsa65KeyPair::generate()?;
        write_secret(&seed_path, pair.secret.expose_seed())?;
        write_atomic(&public_path, pair.public.as_bytes())?;
        let node = Self {
            state_dir: state_dir.to_path_buf(),
            witness_id: witness_id.to_owned(),
            secret: pair.secret,
            public: pair.public,
            trusted_agent_key_ids: Vec::new(),
            ledger: WitnessLedger::default(),
        };
        node.save()?;
        Ok(node)
    }

    pub fn load(state_dir: &Path) -> Result<Self> {
        validate_state_dir(state_dir)?;
        let keys = state_dir.join("keys");
        secure_directory(state_dir)?;
        secure_directory(&keys)?;
        let secret = MlDsa65SecretKey::from_seed(&std::fs::read(keys.join("witness.seed"))?)?;
        let public = MlDsa65PublicKey::from_bytes(&std::fs::read(keys.join("witness.public"))?)?;
        if secret.public_key()?.key_id() != public.key_id() {
            return Err(WitnessError::Config(
                "witness secret and public key do not match".to_owned(),
            ));
        }
        let signed: SignedState = decode_exact(&std::fs::read(state_dir.join("state.cbor"))?)?;
        let embedded_key = MlDsa65PublicKey::from_bytes(&signed.public_key)?;
        if embedded_key.key_id() != public.key_id() {
            return Err(WitnessError::Config(
                "witness state signer does not match the configured key".to_owned(),
            ));
        }
        let signature = MlDsa65Signature::from_bytes(&signed.signature)?;
        public.verify_with_context(&signed.payload, WITNESS_STATE_CONTEXT, &signature)?;
        let document: StateDocument = decode_exact(&signed.payload)?;
        if document.version != PROTOCOL_VERSION {
            return Err(WitnessError::Config(
                "unsupported witness state version".to_owned(),
            ));
        }
        validate_witness_id(&document.witness_id)?;
        validate_trusted_agents(&document.trusted_agent_key_ids)?;
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            witness_id: document.witness_id,
            secret,
            public,
            trusted_agent_key_ids: document.trusted_agent_key_ids,
            ledger: WitnessLedger::from_state(document.ledger)?,
        })
    }

    pub fn status(&self) -> WitnessStatus {
        WitnessStatus {
            witness_id: self.witness_id.clone(),
            witness_key_id: hex::encode(self.public.key_id()),
            trusted_agents: self.trusted_agent_key_ids.len(),
            tracked_scopes: self.ledger.export_state().cursors.len(),
        }
    }

    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.public.as_bytes()
    }

    pub fn pair_agent(&mut self, invitation_uri: &str) -> Result<[u8; 32]> {
        let now = now_unix_ms()?;
        let invitation = PairingInvitation::from_uri(invitation_uri, now)?;
        let endpoint: SocketAddr = invitation
            .endpoint
            .parse()
            .map_err(|_| WitnessError::Config("invalid pairing endpoint".to_owned()))?;
        let remaining_ms = invitation.expires_at_unix_ms.saturating_sub(now).max(1);
        let timeout = Duration::from_millis(remaining_ms);
        let mut stream = TcpStream::connect_timeout(&endpoint, timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let agent_hello: PairingHello = read_cbor_frame(&mut stream)?;
        if agent_hello.session_id != invitation.session_id
            || agent_hello.agent_key_id != invitation.agent_key_id
            || agent_hello.expires_at_unix_ms != invitation.expires_at_unix_ms
        {
            return Err(WitnessError::Config(
                "agent hello does not match pairing invitation".to_owned(),
            ));
        }
        let code = PairingCode::parse(&invitation.code)?;
        let (session, witness_hello) =
            PairingSession::start_viewer(&code, &agent_hello, now_unix_ms()?)?;
        write_cbor_frame(&mut stream, witness_hello)?;
        let key = session.finish(&agent_hello, now_unix_ms()?)?;

        let agent_authenticator: PairingAuthenticator = read_cbor_frame(&mut stream)?;
        key.verify_authenticator(&agent_authenticator, PairingRole::Agent)?;
        if agent_authenticator.identity_label != "agent" {
            return Err(WitnessError::Config(
                "unexpected agent pairing identity label".to_owned(),
            ));
        }
        let agent_public = MlDsa65PublicKey::from_bytes(&agent_authenticator.identity_public_key)?;
        if agent_public.key_id() != invitation.agent_key_id {
            return Err(WitnessError::Config(
                "authenticated agent key does not match invitation".to_owned(),
            ));
        }

        let witness_authenticator = key.authenticator(
            PairingRole::Viewer,
            self.witness_id.clone(),
            self.public.as_bytes().to_vec(),
        )?;
        write_cbor_frame(&mut stream, witness_authenticator)?;
        let receipt: PairingReceipt = read_cbor_frame(&mut stream)?;
        key.verify_receipt(&receipt, self.public.key_id())?;
        self.trust_agent_public_key(agent_public.as_bytes())
    }

    pub fn trust_agent_public_key(&mut self, bytes: &[u8]) -> Result<[u8; 32]> {
        let key_id = MlDsa65PublicKey::from_bytes(bytes)?.key_id();
        match self.trusted_agent_key_ids.binary_search(&key_id) {
            Ok(_) => {}
            Err(index) => self.trusted_agent_key_ids.insert(index, key_id),
        }
        self.save()?;
        Ok(key_id)
    }

    pub fn attest(
        &mut self,
        request_bytes: &[u8],
        now_unix_ms: u64,
    ) -> Result<SignedWitnessStatement> {
        let request = AttestationRequest::from_cbor(request_bytes)?;
        let agent_key_id = request.agent_key_id()?;
        if self
            .trusted_agent_key_ids
            .binary_search(&agent_key_id)
            .is_err()
        {
            return Err(WitnessError::Config(
                "attestation request is not from a trusted agent".to_owned(),
            ));
        }
        let statement = self.ledger.attest(
            &request,
            agent_key_id,
            &self.witness_id,
            &self.secret,
            now_unix_ms,
        )?;
        self.save()?;
        Ok(statement)
    }

    fn save(&self) -> Result<()> {
        let document = StateDocument {
            version: PROTOCOL_VERSION,
            witness_id: self.witness_id.clone(),
            trusted_agent_key_ids: self.trusted_agent_key_ids.clone(),
            ledger: self.ledger.export_state(),
        };
        let payload = minicbor::to_vec(document)
            .map_err(|error| WitnessError::Serialization(error.to_string()))?;
        let signature = self
            .secret
            .sign_with_context(&payload, WITNESS_STATE_CONTEXT)?;
        let signed = SignedState {
            payload,
            public_key: self.public.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        };
        let encoded = minicbor::to_vec(signed)
            .map_err(|error| WitnessError::Serialization(error.to_string()))?;
        write_atomic(&self.state_dir.join("state.cbor"), &encoded)
    }
}

pub fn now_unix_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| WitnessError::Config(error.to_string()))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| WitnessError::Config("system time exceeds u64 milliseconds".to_owned()))
}

fn validate_state_dir(state_dir: &Path) -> Result<()> {
    if !state_dir.is_absolute() {
        return Err(WitnessError::Config(
            "witness state_dir must be absolute".to_owned(),
        ));
    }
    Ok(())
}

fn validate_witness_id(witness_id: &str) -> Result<()> {
    if witness_id.is_empty()
        || witness_id.len() > 128
        || !witness_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(WitnessError::Config(
            "witness id must be a 1-128 character ASCII identifier".to_owned(),
        ));
    }
    Ok(())
}

fn validate_trusted_agents(agents: &[[u8; 32]]) -> Result<()> {
    if agents.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WitnessError::Config(
            "trusted agent key ids must be unique and sorted".to_owned(),
        ));
    }
    Ok(())
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    match std::fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(_) if path.exists() => {
            let backup = path.with_extension("previous");
            if backup.exists() {
                std::fs::remove_file(&backup)?;
            }
            std::fs::rename(path, &backup)?;
            if let Err(error) = std::fs::rename(&temporary, path) {
                let _ = std::fs::rename(&backup, path);
                return Err(error.into());
            }
            std::fs::remove_file(backup)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn secure_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn decode_exact<'a, T>(bytes: &'a [u8]) -> Result<T>
where
    T: Decode<'a, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder
        .decode::<T>()
        .map_err(|error| WitnessError::Serialization(error.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(WitnessError::Serialization(
            "trailing bytes after witness state".to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_shield_core::{
        EntryKind, IntegrityEntry, NormalizedPath, SignedSnapshot, Snapshot,
    };
    use vollcrypt_shield_fs::WitnessPairingServer;

    fn request(agent: &MlDsa65KeyPair, epoch: u64) -> AttestationRequest {
        let entry = IntegrityEntry::new(
            NormalizedPath::new("service.bin").unwrap(),
            EntryKind::File,
            [7; 32],
            [0; 32],
            42,
        );
        let snapshot = Snapshot::new("service", [entry], 10).unwrap();
        AttestationRequest::new(
            epoch,
            &SignedSnapshot::sign(&snapshot, &agent.secret).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn persisted_node_rejects_epoch_replay() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("witness");
        let agent = MlDsa65KeyPair::generate().unwrap();
        let mut node = WitnessNode::initialize(&state_dir, "witness-a").unwrap();
        node.trust_agent_public_key(agent.public.as_bytes())
            .unwrap();
        let first = request(&agent, 1);
        let statement = node.attest(&first.to_cbor().unwrap(), 100).unwrap();
        assert_eq!(statement.verify().unwrap().witness_id, "witness-a");

        let mut reloaded = WitnessNode::load(&state_dir).unwrap();
        assert!(reloaded.attest(&first.to_cbor().unwrap(), 101).is_err());
        assert!(
            reloaded
                .attest(&request(&agent, 2).to_cbor().unwrap(), 102)
                .is_ok()
        );
        assert_eq!(reloaded.status().tracked_scopes, 1);
    }

    #[test]
    fn tampered_signed_state_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("witness");
        WitnessNode::initialize(&state_dir, "witness-a").unwrap();
        let state_path = state_dir.join("state.cbor");
        let mut bytes = std::fs::read(&state_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(state_path, bytes).unwrap();
        assert!(WitnessNode::load(&state_dir).is_err());
    }

    #[test]
    fn loopback_pairing_pins_both_public_identities() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("witness");
        let mut node = WitnessNode::initialize(&state_dir, "witness-a").unwrap();
        let agent = MlDsa65KeyPair::generate().unwrap();
        let agent_key_id = agent.public.key_id();
        let agent_public = agent.public.as_bytes().to_vec();
        let server = WitnessPairingServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
            agent_key_id,
            Duration::from_secs(30),
        )
        .unwrap();
        let invitation = server.invitation_uri().unwrap();
        let pairing = std::thread::spawn(move || {
            let pending = server.accept(&agent_public).unwrap();
            assert_eq!(pending.witness_id(), "witness-a");
            pending.confirm().unwrap();
        });

        assert_eq!(node.pair_agent(&invitation).unwrap(), agent_key_id);
        pairing.join().unwrap();
        assert_eq!(node.status().trusted_agents, 1);
        assert_eq!(
            WitnessNode::load(&state_dir)
                .unwrap()
                .status()
                .trusted_agents,
            1
        );
    }
}
