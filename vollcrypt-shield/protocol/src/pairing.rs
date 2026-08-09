use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{PROTOCOL_VERSION, ProtocolError, Result};

const PAIRING_KEY_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-PAIRING-KEY-v1\0";
const PAIRING_AUTH_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-PAIRING-AUTH-v1\0";
const PAIRING_RECEIPT_DOMAIN: &[u8] = b"VOLLCRYPT-SHIELD-PAIRING-RECEIPT-v1\0";
const MIN_LIFETIME_MS: u64 = 30_000;
const MAX_LIFETIME_MS: u64 = 600_000;
const PAIRING_URI_PREFIX: &str = "vollcrypt-shield://pair/v1/";

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairingCode {
    secret: [u8; 10],
}

impl PairingCode {
    pub fn generate() -> Result<Self> {
        let mut secret = [0_u8; 10];
        getrandom::fill(&mut secret)
            .map_err(|error| ProtocolError::InvalidPairing(error.to_string()))?;
        Ok(Self { secret })
    }

    pub fn parse(value: &str) -> Result<Self> {
        let compact: String = value
            .chars()
            .filter(|character| *character != '-')
            .collect();
        if compact.len() != 20 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ProtocolError::InvalidPairingCode);
        }
        let mut secret = [0_u8; 10];
        hex::decode_to_slice(compact, &mut secret)
            .map_err(|_| ProtocolError::InvalidPairingCode)?;
        Ok(Self { secret })
    }

    pub fn human_readable(&self) -> String {
        let encoded = hex::encode_upper(self.secret);
        encoded
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).expect("hex is ASCII"))
            .collect::<Vec<_>>()
            .join("-")
    }

    fn password(&self) -> Password {
        Password::new(self.secret)
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingCode([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum PairingRole {
    #[n(1)]
    Viewer = 1,
    #[n(2)]
    Agent = 2,
}

impl PairingRole {
    fn opposite(self) -> Self {
        match self {
            Self::Viewer => Self::Agent,
            Self::Agent => Self::Viewer,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct PairingHello {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub session_id: [u8; 16],
    #[n(2)]
    pub agent_key_id: [u8; 32],
    #[n(3)]
    pub role: PairingRole,
    #[n(4)]
    pub issued_at_unix_ms: u64,
    #[n(5)]
    pub expires_at_unix_ms: u64,
    #[n(6)]
    pub message: Vec<u8>,
}

impl PairingHello {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        self.validate(self.issued_at_unix_ms)?;
        minicbor::to_vec(self).map_err(|error| ProtocolError::Serialization(error.to_string()))
    }

    pub fn from_cbor(bytes: &[u8], now_unix_ms: u64) -> Result<Self> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let value = decoder
            .decode::<Self>()
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        if decoder.position() != bytes.len() {
            return Err(ProtocolError::Serialization(
                "trailing bytes after pairing hello".to_owned(),
            ));
        }
        value.validate(now_unix_ms)?;
        Ok(value)
    }

    fn validate(&self, now_unix_ms: u64) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidPairing(
                "unsupported pairing protocol version".to_owned(),
            ));
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self
                .expires_at_unix_ms
                .saturating_sub(self.issued_at_unix_ms)
                > MAX_LIFETIME_MS
        {
            return Err(ProtocolError::InvalidPairing(
                "invalid pairing validity window".to_owned(),
            ));
        }
        if now_unix_ms > self.expires_at_unix_ms {
            return Err(ProtocolError::PairingExpired);
        }
        if self.message.len() != 33 {
            return Err(ProtocolError::InvalidPairing(
                "invalid SPAKE2 message length".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(array)]
pub struct PairingInvitation {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub endpoint: String,
    #[n(2)]
    pub session_id: [u8; 16],
    #[n(3)]
    pub agent_key_id: [u8; 32],
    #[n(4)]
    pub code: String,
    #[n(5)]
    pub expires_at_unix_ms: u64,
}

impl PairingInvitation {
    pub fn new(endpoint: String, hello: &PairingHello, code: &PairingCode) -> Result<Self> {
        if hello.role != PairingRole::Agent {
            return Err(ProtocolError::InvalidPairing(
                "pairing invitation requires an agent hello".to_owned(),
            ));
        }
        let invitation = Self {
            version: PROTOCOL_VERSION,
            endpoint,
            session_id: hello.session_id,
            agent_key_id: hello.agent_key_id,
            code: code.human_readable(),
            expires_at_unix_ms: hello.expires_at_unix_ms,
        };
        invitation.validate(hello.issued_at_unix_ms)?;
        Ok(invitation)
    }

    pub fn to_uri(&self) -> Result<String> {
        self.validate(0)?;
        let encoded = minicbor::to_vec(self)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        Ok(format!("{PAIRING_URI_PREFIX}{}", hex::encode(encoded)))
    }

    pub fn from_uri(uri: &str, now_unix_ms: u64) -> Result<Self> {
        let payload = uri
            .strip_prefix(PAIRING_URI_PREFIX)
            .ok_or_else(|| ProtocolError::InvalidPairing("invalid pairing URI".to_owned()))?;
        let bytes = hex::decode(payload)
            .map_err(|_| ProtocolError::InvalidPairing("invalid pairing URI payload".to_owned()))?;
        let mut decoder = minicbor::Decoder::new(&bytes);
        let invitation = decoder
            .decode::<Self>()
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        if decoder.position() != bytes.len() {
            return Err(ProtocolError::Serialization(
                "trailing bytes after pairing invitation".to_owned(),
            ));
        }
        invitation.validate(now_unix_ms)?;
        Ok(invitation)
    }

    fn validate(&self, now_unix_ms: u64) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidPairing(
                "unsupported pairing invitation version".to_owned(),
            ));
        }
        self.endpoint.parse::<std::net::SocketAddr>().map_err(|_| {
            ProtocolError::InvalidPairing(
                "pairing endpoint must be an IP socket address".to_owned(),
            )
        })?;
        PairingCode::parse(&self.code)?;
        if now_unix_ms > self.expires_at_unix_ms {
            return Err(ProtocolError::PairingExpired);
        }
        Ok(())
    }
}

pub struct PairingSession {
    state: Option<Spake2<Ed25519Group>>,
    hello: PairingHello,
}

impl PairingSession {
    pub fn start_agent(
        code: &PairingCode,
        agent_key_id: [u8; 32],
        now_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Result<(Self, PairingHello)> {
        if !(MIN_LIFETIME_MS..=MAX_LIFETIME_MS).contains(&lifetime_ms) {
            return Err(ProtocolError::InvalidPairing(
                "pairing lifetime must be between 30 and 600 seconds".to_owned(),
            ));
        }
        let expires_at_unix_ms = now_unix_ms
            .checked_add(lifetime_ms)
            .ok_or_else(|| ProtocolError::InvalidPairing("pairing time overflow".to_owned()))?;
        let mut session_id = [0_u8; 16];
        getrandom::fill(&mut session_id)
            .map_err(|error| ProtocolError::InvalidPairing(error.to_string()))?;
        Self::start(
            PairingRole::Agent,
            code,
            session_id,
            agent_key_id,
            now_unix_ms,
            expires_at_unix_ms,
        )
    }

    pub fn start_viewer(
        code: &PairingCode,
        agent_hello: &PairingHello,
        now_unix_ms: u64,
    ) -> Result<(Self, PairingHello)> {
        agent_hello.validate(now_unix_ms)?;
        if agent_hello.role != PairingRole::Agent {
            return Err(ProtocolError::InvalidPairing(
                "viewer requires an agent pairing hello".to_owned(),
            ));
        }
        Self::start(
            PairingRole::Viewer,
            code,
            agent_hello.session_id,
            agent_hello.agent_key_id,
            now_unix_ms,
            agent_hello.expires_at_unix_ms,
        )
    }

    fn start(
        role: PairingRole,
        code: &PairingCode,
        session_id: [u8; 16],
        agent_key_id: [u8; 32],
        now_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<(Self, PairingHello)> {
        let viewer_identity = pairing_identity(b"viewer", &session_id, &agent_key_id);
        let agent_identity = pairing_identity(b"agent", &session_id, &agent_key_id);
        let (state, message) = match role {
            PairingRole::Viewer => Spake2::<Ed25519Group>::start_a(
                &code.password(),
                &Identity::new(&viewer_identity),
                &Identity::new(&agent_identity),
            ),
            PairingRole::Agent => Spake2::<Ed25519Group>::start_b(
                &code.password(),
                &Identity::new(&viewer_identity),
                &Identity::new(&agent_identity),
            ),
        };
        let hello = PairingHello {
            version: PROTOCOL_VERSION,
            session_id,
            agent_key_id,
            role,
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            message,
        };
        hello.validate(now_unix_ms)?;
        Ok((
            Self {
                state: Some(state),
                hello: hello.clone(),
            },
            hello,
        ))
    }

    pub fn finish(mut self, peer: &PairingHello, now_unix_ms: u64) -> Result<PairingKey> {
        peer.validate(now_unix_ms)?;
        if peer.role != self.hello.role.opposite()
            || peer.session_id != self.hello.session_id
            || peer.agent_key_id != self.hello.agent_key_id
            || peer.expires_at_unix_ms != self.hello.expires_at_unix_ms
        {
            return Err(ProtocolError::InvalidPairing(
                "pairing peer transcript does not match the session".to_owned(),
            ));
        }
        if now_unix_ms > self.hello.expires_at_unix_ms {
            return Err(ProtocolError::PairingExpired);
        }
        let mut shared = self
            .state
            .take()
            .ok_or_else(|| ProtocolError::InvalidPairing("pairing state consumed".to_owned()))?
            .finish(&peer.message)
            .map_err(|error| ProtocolError::InvalidPairing(error.to_string()))?;
        let hkdf = Hkdf::<Sha256>::new(Some(&self.hello.session_id), &shared);
        let mut key = [0_u8; 32];
        let mut info = Vec::with_capacity(PAIRING_KEY_DOMAIN.len() + 32);
        info.extend_from_slice(PAIRING_KEY_DOMAIN);
        info.extend_from_slice(&self.hello.agent_key_id);
        hkdf.expand(&info, &mut key)
            .map_err(|_| ProtocolError::InvalidPairing("HKDF expansion failed".to_owned()))?;
        shared.zeroize();
        Ok(PairingKey {
            session_id: self.hello.session_id,
            key,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingKey {
    session_id: [u8; 16],
    key: [u8; 32],
}

impl PairingKey {
    pub fn authenticator(
        &self,
        role: PairingRole,
        identity_label: String,
        identity_public_key: Vec<u8>,
    ) -> Result<PairingAuthenticator> {
        validate_identity_label(&identity_label)?;
        let tag = authentication_tag(
            &self.key,
            &self.session_id,
            role,
            &identity_label,
            &identity_public_key,
        );
        Ok(PairingAuthenticator {
            version: PROTOCOL_VERSION,
            session_id: self.session_id,
            role,
            identity_label,
            identity_public_key,
            tag,
        })
    }

    pub fn verify_authenticator(
        &self,
        authenticator: &PairingAuthenticator,
        expected_role: PairingRole,
    ) -> Result<()> {
        if authenticator.version != PROTOCOL_VERSION
            || authenticator.session_id != self.session_id
            || authenticator.role != expected_role
        {
            return Err(ProtocolError::AuthenticationFailed);
        }
        validate_identity_label(&authenticator.identity_label)?;
        let expected = authentication_tag(
            &self.key,
            &self.session_id,
            authenticator.role,
            &authenticator.identity_label,
            &authenticator.identity_public_key,
        );
        use subtle::ConstantTimeEq;
        if !bool::from(expected.ct_eq(&authenticator.tag)) {
            return Err(ProtocolError::AuthenticationFailed);
        }
        Ok(())
    }

    pub fn receipt(&self, peer_key_id: [u8; 32]) -> PairingReceipt {
        let tag = receipt_tag(&self.key, &self.session_id, &peer_key_id);
        PairingReceipt {
            version: PROTOCOL_VERSION,
            session_id: self.session_id,
            peer_key_id,
            tag,
        }
    }

    pub fn verify_receipt(
        &self,
        receipt: &PairingReceipt,
        expected_peer_key_id: [u8; 32],
    ) -> Result<()> {
        if receipt.version != PROTOCOL_VERSION
            || receipt.session_id != self.session_id
            || receipt.peer_key_id != expected_peer_key_id
        {
            return Err(ProtocolError::AuthenticationFailed);
        }
        use subtle::ConstantTimeEq;
        let expected = receipt_tag(&self.key, &self.session_id, &receipt.peer_key_id);
        if !bool::from(expected.ct_eq(&receipt.tag)) {
            return Err(ProtocolError::AuthenticationFailed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct PairingAuthenticator {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub session_id: [u8; 16],
    #[n(2)]
    pub role: PairingRole,
    #[n(3)]
    pub identity_label: String,
    #[n(4)]
    pub identity_public_key: Vec<u8>,
    #[n(5)]
    pub tag: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct PairingReceipt {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub session_id: [u8; 16],
    #[n(2)]
    pub peer_key_id: [u8; 32],
    #[n(3)]
    pub tag: [u8; 32],
}

fn pairing_identity(role: &[u8], session_id: &[u8; 16], agent_key_id: &[u8; 32]) -> Vec<u8> {
    let mut identity = Vec::with_capacity(32 + role.len() + session_id.len() + agent_key_id.len());
    identity.extend_from_slice(b"VOLLCRYPT-SHIELD-PAIRING-IDENTITY-v1\0");
    identity.extend_from_slice(role);
    identity.extend_from_slice(session_id);
    identity.extend_from_slice(agent_key_id);
    identity
}

fn authentication_tag(
    key: &[u8; 32],
    session_id: &[u8; 16],
    role: PairingRole,
    identity_label: &str,
    public_key: &[u8],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(PAIRING_AUTH_DOMAIN);
    mac.update(session_id);
    mac.update(&[role as u8]);
    mac.update(&(identity_label.len() as u64).to_be_bytes());
    mac.update(identity_label.as_bytes());
    mac.update(&(public_key.len() as u64).to_be_bytes());
    mac.update(public_key);
    mac.finalize().into_bytes().into()
}

fn receipt_tag(key: &[u8; 32], session_id: &[u8; 16], peer_key_id: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(PAIRING_RECEIPT_DOMAIN);
    mac.update(session_id);
    mac.update(peer_key_id);
    mac.finalize().into_bytes().into()
}

fn validate_identity_label(label: &str) -> Result<()> {
    if label.is_empty()
        || label.len() > 128
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProtocolError::InvalidPairing(
            "pairing identity label must be a 1-128 character ASCII identifier".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_code_round_trip_is_redacted() {
        let code = PairingCode::generate().unwrap();
        let displayed = code.human_readable();
        assert_eq!(PairingCode::parse(&displayed).unwrap().secret, code.secret);
        assert_eq!(format!("{code:?}"), "PairingCode([REDACTED])");
    }

    #[test]
    fn invitation_uri_round_trips_and_expires() {
        let code = PairingCode::generate().unwrap();
        let (_agent, hello) = PairingSession::start_agent(&code, [4; 32], 1_000, 60_000).unwrap();
        let invitation =
            PairingInvitation::new("127.0.0.1:49372".to_owned(), &hello, &code).unwrap();
        let uri = invitation.to_uri().unwrap();
        assert_eq!(
            PairingInvitation::from_uri(&uri, 2_000).unwrap(),
            invitation
        );
        assert!(PairingInvitation::from_uri(&uri, 61_001).is_err());
    }

    #[test]
    fn spake2_pairing_authenticates_both_identities() {
        let code = PairingCode::generate().unwrap();
        let (agent, agent_hello) =
            PairingSession::start_agent(&code, [7; 32], 1_000, 60_000).unwrap();
        let (viewer, viewer_hello) =
            PairingSession::start_viewer(&code, &agent_hello, 2_000).unwrap();
        let agent_key = agent.finish(&viewer_hello, 3_000).unwrap();
        let viewer_key = viewer.finish(&agent_hello, 3_000).unwrap();

        let from_agent = agent_key
            .authenticator(PairingRole::Agent, "agent".to_owned(), vec![1, 2, 3])
            .unwrap();
        let from_viewer = viewer_key
            .authenticator(PairingRole::Viewer, "witness".to_owned(), vec![4, 5, 6])
            .unwrap();
        viewer_key
            .verify_authenticator(&from_agent, PairingRole::Agent)
            .unwrap();
        agent_key
            .verify_authenticator(&from_viewer, PairingRole::Viewer)
            .unwrap();
        let receipt = agent_key.receipt([8; 32]);
        viewer_key.verify_receipt(&receipt, [8; 32]).unwrap();
    }

    #[test]
    fn wrong_code_cannot_authenticate() {
        let agent_code = PairingCode::generate().unwrap();
        let viewer_code = PairingCode::generate().unwrap();
        let (agent, agent_hello) =
            PairingSession::start_agent(&agent_code, [9; 32], 1_000, 60_000).unwrap();
        let (viewer, viewer_hello) =
            PairingSession::start_viewer(&viewer_code, &agent_hello, 2_000).unwrap();
        let agent_key = agent.finish(&viewer_hello, 3_000).unwrap();
        let viewer_key = viewer.finish(&agent_hello, 3_000).unwrap();
        let confirmation = agent_key
            .authenticator(PairingRole::Agent, "agent".to_owned(), vec![8; 32])
            .unwrap();
        assert!(
            viewer_key
                .verify_authenticator(&confirmation, PairingRole::Agent)
                .is_err()
        );
    }

    #[test]
    fn expired_or_replayed_hello_is_rejected() {
        let code = PairingCode::generate().unwrap();
        let (_agent, hello) = PairingSession::start_agent(&code, [3; 32], 1_000, 30_000).unwrap();
        assert!(PairingSession::start_viewer(&code, &hello, 31_001).is_err());
    }
}
