use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use vollcrypt_shield_core::MlDsa65PublicKey;
use vollcrypt_shield_protocol::pairing::{
    PairingAuthenticator, PairingCode, PairingHello, PairingInvitation, PairingKey, PairingRole,
    PairingSession,
};
use vollcrypt_shield_protocol::transport::{read_cbor_frame, write_cbor_frame};

use crate::agent::now_unix_ms;
use crate::error::{AgentError, Result};

pub struct WitnessPairingServer {
    listener: TcpListener,
    session: PairingSession,
    hello: PairingHello,
    invitation: PairingInvitation,
}

impl WitnessPairingServer {
    pub fn bind(
        bind_address: SocketAddr,
        advertised_address: Option<SocketAddr>,
        agent_key_id: [u8; 32],
        lifetime: Duration,
    ) -> Result<Self> {
        let listener = TcpListener::bind(bind_address)?;
        listener.set_nonblocking(true)?;
        let local_address = listener.local_addr()?;
        let mut endpoint = advertised_address.unwrap_or(local_address);
        if endpoint.port() == 0 {
            endpoint.set_port(local_address.port());
        }
        if endpoint.ip().is_unspecified() {
            return Err(AgentError::Config(
                "an explicit non-wildcard advertised pairing address is required".to_owned(),
            ));
        }
        let lifetime_ms = u64::try_from(lifetime.as_millis())
            .map_err(|_| AgentError::Config("pairing lifetime exceeds u64".to_owned()))?;
        let code = PairingCode::generate()?;
        let (session, hello) =
            PairingSession::start_agent(&code, agent_key_id, now_unix_ms()?, lifetime_ms)?;
        let invitation = PairingInvitation::new(endpoint.to_string(), &hello, &code)?;
        Ok(Self {
            listener,
            session,
            hello,
            invitation,
        })
    }

    pub fn invitation(&self) -> &PairingInvitation {
        &self.invitation
    }

    pub fn invitation_uri(&self) -> Result<String> {
        Ok(self.invitation.to_uri()?)
    }

    pub fn accept(self, agent_public_key: &[u8]) -> Result<PendingWitnessPairing> {
        let mut stream = loop {
            if now_unix_ms()? > self.hello.expires_at_unix_ms {
                return Err(vollcrypt_shield_protocol::ProtocolError::PairingExpired.into());
            }
            match self.listener.accept() {
                Ok((stream, _peer)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        };

        let remaining_ms = self
            .hello
            .expires_at_unix_ms
            .saturating_sub(now_unix_ms()?)
            .max(1);
        let timeout = Some(Duration::from_millis(remaining_ms));
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;

        write_cbor_frame(&mut stream, self.hello.clone())?;
        let peer_hello: PairingHello = read_cbor_frame(&mut stream)?;
        let key = self.session.finish(&peer_hello, now_unix_ms()?)?;
        let authenticator = key.authenticator(
            PairingRole::Agent,
            "agent".to_owned(),
            agent_public_key.to_vec(),
        )?;
        write_cbor_frame(&mut stream, authenticator)?;
        let peer: PairingAuthenticator = read_cbor_frame(&mut stream)?;
        key.verify_authenticator(&peer, PairingRole::Viewer)?;
        let witness_public = MlDsa65PublicKey::from_bytes(&peer.identity_public_key)?;

        Ok(PendingWitnessPairing {
            stream,
            key,
            witness_id: peer.identity_label,
            witness_public_key: peer.identity_public_key,
            witness_key_id: witness_public.key_id(),
        })
    }
}

pub struct PendingWitnessPairing {
    stream: TcpStream,
    key: PairingKey,
    witness_id: String,
    witness_public_key: Vec<u8>,
    witness_key_id: [u8; 32],
}

impl PendingWitnessPairing {
    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }

    pub fn witness_public_key(&self) -> &[u8] {
        &self.witness_public_key
    }

    pub fn witness_key_id(&self) -> [u8; 32] {
        self.witness_key_id
    }

    pub fn confirm(mut self) -> Result<()> {
        let receipt = self.key.receipt(self.witness_key_id);
        write_cbor_frame(&mut self.stream, receipt)?;
        Ok(())
    }
}
