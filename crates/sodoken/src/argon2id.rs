//! Api functions related to the argon2id password hashing algorithm.

use crate::*;

/// minimum hash length for argon2id pwhash
pub const BYTES_MIN: usize =
    libsodium_sys::crypto_pwhash_argon2id_BYTES_MIN as usize;

/// salt buffer length for argon2id pwhash
pub const SALTBYTES: usize =
    libsodium_sys::crypto_pwhash_argon2id_SALTBYTES as usize;

/// minimum password length for argon2id pwhash
pub const PASSWD_MIN: usize =
    libsodium_sys::crypto_pwhash_argon2id_PASSWD_MIN as usize;

/// maximum password length for argon2id pwhash
pub const PASSWD_MAX: usize =
    libsodium_sys::crypto_pwhash_argon2id_PASSWD_MAX as usize;

/// argon2id pwhash min ops limit
pub const OPSLIMIT_MIN: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN as u64;

/// argon2id pwhash interactive ops limit
pub const OPSLIMIT_INTERACTIVE: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE as u64;

/// argon2id pwhash moderate ops limit
pub const OPSLIMIT_MODERATE: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MODERATE as u64;

/// argon2id pwhash sensitive ops limit
pub const OPSLIMIT_SENSITIVE: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE as u64;

/// argon2id pwhash max ops limit
pub const OPSLIMIT_MAX: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MAX as u64;

/// argon2id pwhash min mem limit
pub const MEMLIMIT_MIN: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MIN as usize;

/// argon2id pwhash interactive mem limit
pub const MEMLIMIT_INTERACTIVE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE as usize;

/// argon2id pwhash moderate mem limit
pub const MEMLIMIT_MODERATE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MODERATE as usize;

/// argon2id pwhash sensitive mem limit
pub const MEMLIMIT_SENSITIVE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE as usize;

/// argon2id13 password hashing scheme
pub async fn hash<H, P, S>(
    hash: H,
    passphrase: P,
    salt: S,
    ops_limit: u64,
    mem_limit: usize,
) -> SodokenResult<()>
where
    H: AsBufWrite,
    P: AsBufRead,
    S: AsBufReadSized<SALTBYTES>,
{
    tokio_exec(move || {
        let mut hash = hash.write_lock();
        let passphrase = passphrase.read_lock();
        let salt = salt.read_lock_sized();
        safe::sodium::crypto_pwhash_argon2id(
            &mut hash,
            &passphrase,
            &salt,
            ops_limit,
            mem_limit,
        )
    })
    .await
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn argon2id() -> SodokenResult<()> {
        let pass = BufRead::new_no_lock(b"my passphrase");
        let salt: BufReadSized<{ argon2id::SALTBYTES }> =
            BufReadSized::new_no_lock([0xdb; argon2id::SALTBYTES]);
        let hash = BufWrite::new_no_lock(argon2id::BYTES_MIN);
        argon2id::hash(
            hash.clone(),
            pass,
            salt,
            argon2id::OPSLIMIT_INTERACTIVE,
            argon2id::MEMLIMIT_INTERACTIVE,
        )
        .await?;
        assert_eq!(
            "[236, 88, 226, 164, 99, 188, 201, 149, 83, 218, 26, 28, 193, 215, 226, 72]",
            format!("{:?}", &*hash.read_lock()),
        );
        Ok(())
    }
}
