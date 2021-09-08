/// Error Kind Enum for Sodoken OneErr.
#[derive(Debug)]
#[non_exhaustive]
pub enum SodokenErrKind {
    /// we were unable to allocate memory
    AllocationFailed,

    /// the output hash size for this call didn't fall within constraints
    BadHashSize,

    /// the salt size for this call didn't fall within constraints
    BadSaltSize,

    /// the key size for this call didn't fall within constraints
    BadKeySize,

    /// the public key size for this call didn't fall within constraints
    BadPublicKeySize,

    /// the secret key size for this call didn't fall within constraints
    BadSecretKeySize,

    /// improper size for signature
    BadSignatureSize,

    /// improper size for seed
    BadSeedSize,

    /// improper size for cipher
    BadCipherSize,

    /// improper size for nonce
    BadNonceSize,

    /// improper size for message
    BadMessageSize,

    /// the passphrase size for this call didn't fall within constraints
    BadPassphraseSize,

    /// the ops limit for this call didn't fall within constraints
    BadOpsLimit,

    /// the mem limit for this call didn't fall within constraints
    BadMemLimit,

    /// bad bounds for write operation
    WriteOverflow,

    /// Internal libsodium error
    InternalSodium,

    /// OtherErrorType
    Other,
}

impl From<SodokenErrKind> for &'static str {
    fn from(k: SodokenErrKind) -> Self {
        use SodokenErrKind::*;
        match k {
            AllocationFailed => "AllocationFailed",
            BadHashSize => "BadHashSize",
            BadSaltSize => "BadSaltSize",
            BadKeySize => "BadKeySize",
            BadPublicKeySize => "BadPublicKeySize",
            BadSecretKeySize => "BadSecretKeySize",
            BadSignatureSize => "BadSignatureSize",
            BadSeedSize => "BadSeedSize",
            BadCipherSize => "BadCipherSize",
            BadNonceSize => "BadNonceSize",
            BadMessageSize => "BadMessageSize",
            BadPassphraseSize => "BadPassphraseSize",
            BadOpsLimit => "BadOpsLimit",
            BadMemLimit => "BadMemLimit",
            WriteOverflow => "WriteOverflow",
            InternalSodium => "InternalSodium",
            _ => "Other",
        }
    }
}

impl From<&str> for SodokenErrKind {
    fn from(e: &str) -> Self {
        use SodokenErrKind::*;
        match e {
            "AllocationFailed" => AllocationFailed,
            "BadHashSize" => BadHashSize,
            "BadSaltSize" => BadSaltSize,
            "BadKeySize" => BadKeySize,
            "BadPublicKeySize" => BadPublicKeySize,
            "BadSecretKeySize" => BadSecretKeySize,
            "BadSignatureSize" => BadSignatureSize,
            "BadSeedSize" => BadSeedSize,
            "BadCipherSize" => BadCipherSize,
            "BadNonceSize" => BadNonceSize,
            "BadMessageSize" => BadMessageSize,
            "BadPassphraseSize" => BadPassphraseSize,
            "BadOpsLimit" => BadOpsLimit,
            "BadMemLimit" => BadMemLimit,
            "WriteOverflow" => WriteOverflow,
            "InternalSodium" => InternalSodium,
            _ => Other,
        }
    }
}

impl std::str::FromStr for SodokenErrKind {
    type Err = one_err::OneErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.into())
    }
}

impl From<&one_err::OneErr> for SodokenErrKind {
    fn from(e: &one_err::OneErr) -> Self {
        e.str_kind().into()
    }
}

impl From<SodokenErrKind> for one_err::OneErr {
    fn from(k: SodokenErrKind) -> Self {
        one_err::OneErr::new(<&'static str>::from(k))
    }
}

/// Sodoken Result Type
pub type SodokenResult<T> = Result<T, one_err::OneErr>;
