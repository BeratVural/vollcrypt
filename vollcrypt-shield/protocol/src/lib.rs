#![forbid(unsafe_code)]

pub mod control_plane;
mod error;
pub mod fleet_api;
pub mod offline;
pub mod pairing;
pub mod transport;
pub mod witness;

pub use error::{ProtocolError, Result};

pub const PROTOCOL_VERSION: u16 = 1;
