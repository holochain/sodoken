/// Error type for holochain_crypto.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SodokenError {
    /// we were unable to allocate memory
    #[error("AllocationFailed")]
    AllocationFailed,

    /// the output hash size for this call didn't fall within constraints
    #[error("BadHashSize")]
    BadHashSize,

    /// the salt size for this call didn't fall within constraints
    #[error("BadSaltSize")]
    BadSaltSize,

    /// the key size for this call didn't fall within constraints
    #[error("BadKeySize")]
    BadKeySize,

    /// the public key size for this call didn't fall within constraints
    #[error("BadPublicKeySize")]
    BadPublicKeySize,

    /// the secret key size for this call didn't fall within constraints
    #[error("BadSecretKeySize")]
    BadSecretKeySize,

    /// improper size for signature
    #[error("BadSignatureSize")]
    BadSignatureSize,

    /// improper size for seed
    #[error("BadSeedSize")]
    BadSeedSize,

    /// the passphrase size for this call didn't fall within constraints
    #[error("BadPassphraseSize")]
    BadPassphraseSize,

    /// the ops limit for this call didn't fall within constraints
    #[error("BadOpsLimit")]
    BadOpsLimit,

    /// the mem limit for this call didn't fall within constraints
    #[error("BadMemLimit")]
    BadMemLimit,

    /// bad bounds for write operation
    #[error("WriteOverflow")]
    WriteOverflow,

    /// Internal libsodium error
    #[error("InternalSodium")]
    InternalSodium,

    /// generic internal error
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl SodokenError {
    /// Build an "Other" type SodokenError.
    pub fn other(
        e: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        SodokenError::Other(e.into())
    }
}

impl From<String> for SodokenError {
    fn from(s: String) -> Self {
        #[derive(Debug, thiserror::Error)]
        struct OtherError(String);
        impl std::fmt::Display for OtherError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        SodokenError::other(OtherError(s))
    }
}

impl From<&str> for SodokenError {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<SodokenError> for () {
    fn from(_: SodokenError) {}
}

/// Result type for holochain_crypto.
pub type SodokenResult<T> = Result<T, SodokenError>;
