use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use vollcrypt_shield_core::{MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};

use crate::{PROTOCOL_VERSION, ProtocolError, Result};

const RESPONSE_SIGNATURE_CONTEXT: &[u8] = b"Vollcrypt Shield Fleet API Response v1";
pub const MAX_FLEET_API_REQUEST_BYTES: usize = 65_536;
pub const MAX_FLEET_API_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_FLEET_API_CLOCK_SKEW_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum FleetApiOperation {
    #[n(1)]
    Status = 1,
    #[n(2)]
    Enroll = 2,
    #[n(3)]
    IngestSummary = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum FleetApiStatus {
    #[n(1)]
    Ok = 1,
    #[n(2)]
    InvalidRequest = 2,
    #[n(3)]
    AuthenticationFailed = 3,
    #[n(4)]
    Conflict = 4,
    #[n(5)]
    InternalError = 5,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct FleetApiRequest {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub request_id: [u8; 16],
    #[n(2)]
    pub issued_at_unix_ms: u64,
    #[n(3)]
    pub operation: FleetApiOperation,
    #[n(4)]
    pub credential: Vec<u8>,
    #[n(5)]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct FleetApiResponseClaim {
    #[n(0)]
    pub version: u16,
    #[n(1)]
    pub request_id: [u8; 16],
    #[n(2)]
    pub generated_at_unix_ms: u64,
    #[n(3)]
    pub status: FleetApiStatus,
    #[n(4)]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct SignedFleetApiResponse {
    #[n(0)]
    payload: Vec<u8>,
    #[n(1)]
    public_key: Vec<u8>,
    #[n(2)]
    signature: Vec<u8>,
}

impl FleetApiRequest {
    pub fn new(
        operation: FleetApiOperation,
        issued_at_unix_ms: u64,
        credential: Vec<u8>,
        body: Vec<u8>,
    ) -> Result<Self> {
        let mut request_id = [0_u8; 16];
        getrandom::fill(&mut request_id).map_err(|_| {
            ProtocolError::InvalidFleetApi("request id generation failed".to_owned())
        })?;
        let request = Self {
            version: PROTOCOL_VERSION,
            request_id,
            issued_at_unix_ms,
            operation,
            credential,
            body,
        };
        request.validate_shape()?;
        Ok(request)
    }

    pub fn validate_at(&self, now_unix_ms: u64) -> Result<()> {
        self.validate_shape()?;
        if self.issued_at_unix_ms > now_unix_ms.saturating_add(MAX_FLEET_API_CLOCK_SKEW_MS)
            || now_unix_ms.saturating_sub(self.issued_at_unix_ms) > MAX_FLEET_API_CLOCK_SKEW_MS
        {
            return Err(ProtocolError::InvalidFleetApi(
                "request timestamp is outside the accepted window".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let encoded = minicbor::to_vec(self)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_FLEET_API_REQUEST_BYTES {
            return Err(ProtocolError::InvalidFleetApi(
                "request exceeds its encoded size limit".to_owned(),
            ));
        }
        Ok(encoded)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_FLEET_API_REQUEST_BYTES {
            return Err(ProtocolError::InvalidFleetApi(
                "request exceeds its encoded size limit".to_owned(),
            ));
        }
        let request: Self = decode_exact(bytes, "fleet API request")?;
        request.validate_shape()?;
        Ok(request)
    }

    fn validate_shape(&self) -> Result<()> {
        let shape_is_valid = match self.operation {
            FleetApiOperation::Status => self.credential.is_empty() && self.body.is_empty(),
            FleetApiOperation::Enroll => {
                !self.credential.is_empty()
                    && self.credential.len() <= 256
                    && !self.body.is_empty()
                    && self.body.len() <= 16_384
            }
            FleetApiOperation::IngestSummary => {
                self.credential.is_empty() && !self.body.is_empty() && self.body.len() <= 16_384
            }
        };
        if self.version != PROTOCOL_VERSION
            || self.request_id == [0; 16]
            || self.issued_at_unix_ms == 0
            || !shape_is_valid
        {
            return Err(ProtocolError::InvalidFleetApi(
                "request version, identifier, timestamp, or operation shape is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

impl FleetApiResponseClaim {
    pub fn new(
        request_id: [u8; 16],
        generated_at_unix_ms: u64,
        status: FleetApiStatus,
        body: Vec<u8>,
    ) -> Result<Self> {
        let claim = Self {
            version: PROTOCOL_VERSION,
            request_id,
            generated_at_unix_ms,
            status,
            body,
        };
        claim.validate()?;
        Ok(claim)
    }

    fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION
            || self.request_id == [0; 16]
            || self.generated_at_unix_ms == 0
            || self.body.len() > MAX_FLEET_API_RESPONSE_BYTES
        {
            return Err(ProtocolError::InvalidFleetApi(
                "response claim contains invalid identifiers or bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

impl SignedFleetApiResponse {
    pub fn sign(claim: &FleetApiResponseClaim, secret: &MlDsa65SecretKey) -> Result<Self> {
        claim.validate()?;
        let payload = minicbor::to_vec(claim)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        let public = secret.public_key()?;
        let signature = secret.sign_with_context(&payload, RESPONSE_SIGNATURE_CONTEXT)?;
        Ok(Self {
            payload,
            public_key: public.as_bytes().to_vec(),
            signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify(&self) -> Result<(FleetApiResponseClaim, MlDsa65PublicKey)> {
        let public = MlDsa65PublicKey::from_bytes(&self.public_key)?;
        let signature = MlDsa65Signature::from_bytes(&self.signature)?;
        public.verify_with_context(&self.payload, RESPONSE_SIGNATURE_CONTEXT, &signature)?;
        let claim: FleetApiResponseClaim = decode_exact(&self.payload, "fleet API response")?;
        claim.validate()?;
        Ok((claim, public))
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let encoded = minicbor::to_vec(self)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_FLEET_API_RESPONSE_BYTES.saturating_add(8_192) {
            return Err(ProtocolError::InvalidFleetApi(
                "signed response exceeds its encoded size limit".to_owned(),
            ));
        }
        Ok(encoded)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_FLEET_API_RESPONSE_BYTES.saturating_add(8_192) {
            return Err(ProtocolError::InvalidFleetApi(
                "signed response exceeds its encoded size limit".to_owned(),
            ));
        }
        decode_exact(bytes, "signed fleet API response")
    }
}

fn decode_exact<'bytes, Value>(bytes: &'bytes [u8], label: &str) -> Result<Value>
where
    Value: Decode<'bytes, ()>,
{
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = decoder
        .decode::<Value>()
        .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::Serialization(format!(
            "trailing bytes after {label}"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vollcrypt_shield_core::MlDsa65KeyPair;

    #[test]
    fn request_shape_and_time_window_are_enforced() {
        let request =
            FleetApiRequest::new(FleetApiOperation::Status, 1_000, vec![], vec![]).unwrap();
        let decoded = FleetApiRequest::from_cbor(&request.to_cbor().unwrap()).unwrap();
        decoded.validate_at(1_100).unwrap();
        assert!(decoded.validate_at(400_001).is_err());

        assert!(FleetApiRequest::new(FleetApiOperation::Status, 1_000, vec![1], vec![]).is_err());
        assert!(FleetApiRequest::new(FleetApiOperation::Enroll, 1_000, vec![], vec![1]).is_err());
    }

    #[test]
    fn signed_response_binds_request_status_body_and_signer() {
        let signer = MlDsa65KeyPair::generate().unwrap();
        let claim = FleetApiResponseClaim::new(
            [3; 16],
            2_000,
            FleetApiStatus::Ok,
            br#"{"registeredAgents":1}"#.to_vec(),
        )
        .unwrap();
        let signed = SignedFleetApiResponse::sign(&claim, &signer.secret).unwrap();
        let decoded = SignedFleetApiResponse::from_cbor(&signed.to_cbor().unwrap()).unwrap();
        let (verified, public) = decoded.verify().unwrap();
        assert_eq!(verified, claim);
        assert_eq!(public.as_bytes(), signer.public.as_bytes());

        let mut tampered = signed.to_cbor().unwrap();
        let midpoint = tampered.len() / 2;
        tampered[midpoint] ^= 1;
        assert!(
            SignedFleetApiResponse::from_cbor(&tampered)
                .and_then(|value| value.verify())
                .is_err()
        );
    }
}
