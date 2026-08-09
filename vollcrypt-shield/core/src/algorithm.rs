use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
#[repr(u8)]
pub enum HashAlgorithm {
    #[n(1)]
    #[default]
    Sha256 = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[cbor(index_only)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    #[n(1)]
    #[default]
    MlDsa65 = 1,
}
