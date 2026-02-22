use serde::{Deserialize, Serialize};

/// Represents a single authorized device in the registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    /// Unique identifier for the device (e.g., a UUID or generated ID)
    pub device_id: String,
    /// Human-readable name for the device (e.g., "Work Phone", "Laptop")
    pub name: String,
    /// Unix timestamp when the device was added
    pub added_at: u64,
    /// Ed25519 Public Key associated with this device, encoded as hex or base64.
    pub public_key: String,
    /// Status indicating if this device has been revoked
    pub is_revoked: bool,
}

/// The Device Authorization Registry storing a list of user devices.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefaultDeviceRegistry {
    /// List of devices registered by the user
    pub devices: Vec<Device>,
}

impl DefaultDeviceRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Adds a new device to the registry if it doesn't already exist by device_id.
    pub fn add_device(&mut self, device: Device) -> Result<(), &'static str> {
        if self.devices.iter().any(|d| d.device_id == device.device_id) {
            return Err("Device with this ID already exists in the registry.");
        }
        self.devices.push(device);
        Ok(())
    }

    /// Revokes a device by marking `is_revoked` as true.
    pub fn revoke_device(&mut self, device_id: &str) -> Result<(), &'static str> {
        if let Some(device) = self.devices.iter_mut().find(|d| d.device_id == device_id) {
            if device.is_revoked {
                return Err("Device is already revoked.");
            }
            device.is_revoked = true;
            Ok(())
        } else {
            Err("Device not found.")
        }
    }

    /// Returns a list of active (non-revoked) devices.
    pub fn get_active_devices(&self) -> Vec<Device> {
        self.devices
            .iter()
            .filter(|d| !d.is_revoked)
            .cloned()
            .collect()
    }

    /// Returns a list of all devices in the registry, including revoked ones.
    pub fn get_all_devices(&self) -> Vec<Device> {
        self.devices.clone()
    }

    /// Serializes active devices to a JSON string.
    pub fn get_active_devices_json(&self) -> Result<String, &'static str> {
        let active = self.get_active_devices();
        serde_json::to_string(&active).map_err(|_| "Failed to serialize active devices.")
    }

    /// Serializes the registry to a JSON string.
    pub fn to_json(&self) -> Result<String, &'static str> {
        serde_json::to_string(self).map_err(|_| "Failed to serialize device registry.")
    }

    /// Deserializes the registry from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, &'static str> {
        serde_json::from_str(json).map_err(|_| "Failed to deserialize device registry.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_registry_operations() {
        let mut registry = DefaultDeviceRegistry::new();

        let device1 = Device {
            device_id: "dev-001".to_string(),
            name: "Work Phone".to_string(),
            added_at: 1700000000,
            public_key: "dummy_pk_123".to_string(),
            is_revoked: false,
        };

        // Add
        assert!(registry.add_device(device1.clone()).is_ok());
        assert_eq!(registry.get_all_devices().len(), 1);

        // Add duplicate (should fail)
        assert!(registry.add_device(device1).is_err());

        let device2 = Device {
            device_id: "dev-002".to_string(),
            name: "Home Laptop".to_string(),
            added_at: 1700000050,
            public_key: "dummy_pk_456".to_string(),
            is_revoked: false,
        };
        assert!(registry.add_device(device2).is_ok());
        assert_eq!(registry.get_active_devices().len(), 2);

        // Revoke
        assert!(registry.revoke_device("dev-001").is_ok());
        assert_eq!(registry.get_active_devices().len(), 1);
        assert_eq!(registry.get_all_devices().len(), 2);

        // Revoke missing
        assert!(registry.revoke_device("dev-999").is_err());
        
        // Revoke already revoked
        assert!(registry.revoke_device("dev-001").is_err());
    }

    #[test]
    fn test_registry_serialization() {
        let mut registry = DefaultDeviceRegistry::new();
        registry
            .add_device(Device {
                device_id: "dev-1".to_string(),
                name: "Phone".to_string(),
                added_at: 100,
                public_key: "abc".to_string(),
                is_revoked: false,
            })
            .unwrap();

        let json = registry.to_json().expect("Should serialize");
        let restored_registry = DefaultDeviceRegistry::from_json(&json).expect("Should deserialize");

        assert_eq!(restored_registry.devices.len(), 1);
        assert_eq!(restored_registry.devices[0].name, "Phone");
    }
}
