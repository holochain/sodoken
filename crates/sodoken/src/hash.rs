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
async fn generichash_inner<H, M, K>(
    hash: H,
    message: M,
    key: Option<K>,
) -> SodokenResult<()>
where
    H: AsBufWrite,
    M: AsBufRead,
    K: AsBufRead,
{
    tokio_exec(move || {
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

/// blake2b hashing scheme
pub async fn generichash_with_key<H, M, K>(
    hash: H,
    message: M,
    key: K,
) -> SodokenResult<()>
where
    H: AsBufWrite,
    M: AsBufRead,
    K: AsBufRead,
{
    generichash_inner(hash, message, Some(key)).await
}

/// blake2b hashing scheme
pub async fn generichash<H, M>(hash: H, message: M) -> SodokenResult<()>
where
    H: AsBufWrite,
    M: AsBufRead,
{
    generichash_inner::<H, M, BufRead>(hash, message, None).await
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
pub async fn pwhash_argon2id<H, P, S>(
    hash: H,
    passphrase: P,
    salt: S,
    ops_limit: u64,
    mem_limit: usize,
) -> SodokenResult<()>
where
    H: AsBufWrite,
    P: AsBufRead,
    S: AsBufRead,
{
    tokio_exec(move || {
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
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn generichash() -> SodokenResult<()> {
        let msg = BufRead::new_no_lock(b"test message");
        let hash = BufWrite::new_no_lock(hash::GENERICHASH_BYTES_MIN);
        hash::generichash(hash.clone(), msg.clone()).await?;
        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );

        // also check that a trait-object works
        let msg2 = msg.clone();
        let msg2: Box<dyn AsBufRead> = Box::new(msg2);
        hash::generichash(hash.clone(), msg2).await?;
        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );

        // also check that arc trait-object works
        let msg3 = msg.clone();
        let msg3: Arc<dyn AsBufRead> = Arc::new(msg3);
        hash::generichash(hash.clone(), msg3).await?;
        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pwhash_argon2id() -> SodokenResult<()> {
        let pass = BufRead::new_no_lock(b"my passphrase");
        let salt =
            BufRead::new_no_lock(&[0xdb; hash::PWHASH_ARGON2ID_SALTBYTES]);
        let hash = BufWrite::new_no_lock(hash::PWHASH_ARGON2ID_BYTES_MIN);
        hash::pwhash_argon2id(
            hash.clone(),
            pass,
            salt,
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
