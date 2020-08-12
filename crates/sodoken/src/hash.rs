//! Api functions related to digests and hashing.

use crate::*;

/// minimum generichash/blake2b output hash size
pub const GENERICHASH_BYTES_MIN: usize =
    libsodium_sys::crypto_generichash_BYTES_MIN as usize;

/// maximum generichash/blake2b output hash size
pub const GENERICHASH_BYTES_MAX: usize =
    libsodium_sys::crypto_generichash_BYTES_MAX as usize;

/// minimum generichash/blake2b key size
pub const GENERICHASH_KEYBYTES_MIN: usize =
    libsodium_sys::crypto_generichash_BYTES_MIN as usize;

/// maximum generichash/blake2b key size
pub const GENERICHASH_KEYBYTES_MAX: usize =
    libsodium_sys::crypto_generichash_BYTES_MAX as usize;

/// blake2b hashing scheme
pub async fn generichash(
    hash: &mut Buffer,
    message: &Buffer,
    key: Option<&Buffer>,
) -> SodokenResult<()> {
    let hash = hash.clone();
    let message = message.clone();
    let key = key.cloned();
    rayon_exec(move || {
        let mut hash = hash.write_lock();
        let message = message.read_lock();
        match key {
            Some(key) => {
                let key = key.read_lock();
                safe::sodium::crypto_generichash(
                    &mut hash,
                    &message,
                    Some(&key),
                )
            }
            None => safe::sodium::crypto_generichash(&mut hash, &message, None),
        }
    })
    .await
}

/// minimum hash length for argon2id pwhash
pub const PWHASH_ARGON2ID_BYTES_MIN: usize =
    libsodium_sys::crypto_pwhash_argon2id_BYTES_MIN as usize;

/// salt buffer length for argon2id pwhash
pub const PWHASH_ARGON2ID_SALTBYTES: usize =
    libsodium_sys::crypto_pwhash_argon2id_SALTBYTES as usize;

/// minimum password length for argon2id pwhash
pub const PWHASH_ARGON2ID_PASSWD_MIN: usize =
    libsodium_sys::crypto_pwhash_argon2id_PASSWD_MIN as usize;

/// maximum password length for argon2id pwhash
pub const PWHASH_ARGON2ID_PASSWD_MAX: usize =
    libsodium_sys::crypto_pwhash_argon2id_PASSWD_MAX as usize;

/// argon2id pwhash min ops limit
pub const PWHASH_ARGON2ID_OPSLIMIT_MIN: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN as u64;

/// argon2id pwhash interactive ops limit
pub const PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE as u64;

/// argon2id pwhash moderate ops limit
pub const PWHASH_ARGON2ID_OPSLIMIT_MODERATE: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MODERATE as u64;

/// argon2id pwhash sensitive ops limit
pub const PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE as u64;

/// argon2id pwhash max ops limit
pub const PWHASH_ARGON2ID_OPSLIMIT_MAX: u64 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MAX as u64;

/// argon2id pwhash min mem limit
pub const PWHASH_ARGON2ID_MEMLIMIT_MIN: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MIN as usize;

/// argon2id pwhash interactive mem limit
pub const PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE as usize;

/// argon2id pwhash moderate mem limit
pub const PWHASH_ARGON2ID_MEMLIMIT_MODERATE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MODERATE as usize;

/// argon2id pwhash sensitive mem limit
pub const PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE: usize =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE as usize;

/// argon2id13 password hashing scheme
pub async fn pwhash_argon2id(
    hash: &mut Buffer,
    passphrase: &Buffer,
    salt: &Buffer,
    ops_limit: u64,
    mem_limit: usize,
) -> SodokenResult<()> {
    let hash = hash.clone();
    let passphrase = passphrase.clone();
    let salt = salt.clone();
    rayon_exec(move || {
        let mut hash = hash.write_lock();
        let passphrase = passphrase.read_lock();
        let salt = salt.read_lock();
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

    #[tokio::test(threaded_scheduler)]
    async fn generichash() -> SodokenResult<()> {
        let msg: Buffer = b"test message".to_vec().into();
        let mut hash = Buffer::new(hash::GENERICHASH_BYTES_MIN);
        hash::generichash(&mut hash, &msg, None).await?;
        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );
        Ok(())
    }

    #[tokio::test(threaded_scheduler)]
    async fn pwhash_argon2id() -> SodokenResult<()> {
        let pass: Buffer = b"my passphrase".to_vec().into();
        let salt: Buffer = vec![0xdb; hash::PWHASH_ARGON2ID_SALTBYTES].into();
        let mut hash = Buffer::new(hash::PWHASH_ARGON2ID_BYTES_MIN);
        hash::pwhash_argon2id(
            &mut hash,
            &pass,
            &salt,
            hash::PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE,
            hash::PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE,
        )
        .await?;
        assert_eq!(
            "[236, 88, 226, 164, 99, 188, 201, 149, 83, 218, 26, 28, 193, 215, 226, 72]",
            format!("{:?}", &*hash.read_lock()),
        );
        Ok(())
    }
}
