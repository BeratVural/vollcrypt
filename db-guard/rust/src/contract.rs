use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;

pub const DB_GUARD_CONTRACT_VERSION: u8 = 1;
pub const SUPPORTED_KEY_VERSIONS: [&str; 2] = ["1", "2"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbGuardContractV1 {
    pub contract_version: u8,
    pub active_key_version: String,
    pub resources: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbGuardContractError {
    pub code: &'static str,
    message: String,
}

impl DbGuardContractError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for DbGuardContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Vollcrypt DbGuard contract [{}]: {}",
            self.code, self.message
        )
    }
}

impl Error for DbGuardContractError {}

pub fn validate_orm_contract(
    contract: &DbGuardContractV1,
    keys: &HashMap<String, Vec<u8>>,
) -> Result<(), DbGuardContractError> {
    if contract.contract_version != DB_GUARD_CONTRACT_VERSION {
        return Err(DbGuardContractError::new(
            "UNSUPPORTED_CONTRACT_VERSION",
            format!(
                "expected {}, got {}.",
                DB_GUARD_CONTRACT_VERSION, contract.contract_version
            ),
        ));
    }

    if keys.is_empty() {
        return Err(DbGuardContractError::new(
            "INVALID_KEYRING",
            "keyring must not be empty.",
        ));
    }
    for (version, key) in keys {
        if !SUPPORTED_KEY_VERSIONS.contains(&version.as_str()) {
            return Err(DbGuardContractError::new(
                "INVALID_KEYRING",
                format!("unsupported key version {version}."),
            ));
        }
        if key.len() != 32 {
            return Err(DbGuardContractError::new(
                "INVALID_KEYRING",
                format!("key version {version} must be 32 bytes."),
            ));
        }
    }
    if !keys.contains_key(&contract.active_key_version) {
        return Err(DbGuardContractError::new(
            "INVALID_KEYRING",
            format!(
                "active key version {} is not present in the keyring.",
                contract.active_key_version
            ),
        ));
    }

    if contract.resources.is_empty() {
        return Err(DbGuardContractError::new(
            "INVALID_RESOURCE_SCOPE",
            "resources must not be empty.",
        ));
    }
    for (resource, fields) in &contract.resources {
        if resource.trim().is_empty()
            || fields.is_empty()
            || fields.iter().any(|field| field.trim().is_empty())
        {
            return Err(DbGuardContractError::new(
                "INVALID_RESOURCE_SCOPE",
                format!("resource {resource:?} must contain valid field names."),
            ));
        }
    }

    Ok(())
}

pub fn configure_orm_contract(
    contract: &DbGuardContractV1,
    keys: &HashMap<String, Vec<u8>>,
) -> Result<(), DbGuardContractError> {
    validate_orm_contract(contract, keys)?;

    crate::clear_registry();
    for (version, key) in keys {
        crate::set_key(version, key);
    }
    crate::set_active_version(&contract.active_key_version)
        .map_err(|message| DbGuardContractError::new("INVALID_KEYRING", message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> DbGuardContractV1 {
        DbGuardContractV1 {
            contract_version: DB_GUARD_CONTRACT_VERSION,
            active_key_version: "2".to_string(),
            resources: BTreeMap::from([(
                "User".to_string(),
                vec!["email".to_string(), "card".to_string()],
            )]),
        }
    }

    fn keys() -> HashMap<String, Vec<u8>> {
        HashMap::from([
            ("1".to_string(), vec![1; 32]),
            ("2".to_string(), vec![2; 32]),
        ])
    }

    #[test]
    fn validates_the_shared_diesel_and_seaorm_contract() {
        assert_eq!(validate_orm_contract(&contract(), &keys()), Ok(()));
    }

    #[test]
    fn rejects_contract_version_keyring_and_resource_mismatches() {
        let mut invalid_version = contract();
        invalid_version.contract_version = 2;
        assert_eq!(
            validate_orm_contract(&invalid_version, &keys())
                .expect_err("version must fail")
                .code,
            "UNSUPPORTED_CONTRACT_VERSION"
        );

        let mut missing_active = keys();
        missing_active.remove("2");
        assert_eq!(
            validate_orm_contract(&contract(), &missing_active)
                .expect_err("missing active key must fail")
                .code,
            "INVALID_KEYRING"
        );

        let mut empty_resources = contract();
        empty_resources.resources.clear();
        assert_eq!(
            validate_orm_contract(&empty_resources, &keys())
                .expect_err("empty resources must fail")
                .code,
            "INVALID_RESOURCE_SCOPE"
        );
    }
}
