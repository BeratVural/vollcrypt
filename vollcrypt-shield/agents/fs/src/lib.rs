#![forbid(unsafe_code)]

pub mod agent;
pub mod audit_store;
pub mod config;
pub mod error;
pub mod ipc;
pub mod metadata;
pub mod notification;
pub mod pairing;
pub mod response;
pub mod scanner;
pub mod state;
pub mod vault;
pub mod witness_registry;

pub use agent::ShieldAgent;
pub use config::{AgentConfig, NotificationConfig, ScopeConfig};
pub use error::{AgentError, Result};
pub use ipc::AgentStatus;
#[cfg(unix)]
pub use ipc::{LocalStatusServer, query_local_status};
pub use pairing::{PendingWitnessPairing, WitnessPairingServer};
pub use response::{ResponseEngine, ResponseOutcome};
pub use scanner::{ScanResult, Scanner};
pub use witness_registry::{WitnessRegistry, WitnessRegistryEntry};

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
