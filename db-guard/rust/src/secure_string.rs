macro_rules! impl_secure_encrypted_string {
    ($type:ty) => {
        impl Drop for $type {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.0);
            }
        }

        impl std::fmt::Debug for $type {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("EncryptedString([REDACTED])")
            }
        }
    };
}

pub(crate) use impl_secure_encrypted_string;
