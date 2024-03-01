//! Api functions related to the argon2id password hashing algorithm.
//!
//! Argon2 is a password hashing scheme designed to be both cpu and
//! memory hard. You can configure this hardness with the `ops_limit`
//! for how difficult it is cpu-wise, and `mem_limit` for how much
//! memory it will use during the operation. For tests, please use
//! `MIN`, otherwise your tests will take a long time.
//!
//! #### Example
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! // generate salt
//! let salt = sodoken::BufWriteSized::new_no_lock();
//! sodoken::random::bytes_buf(salt.clone()).await.unwrap();
//! let salt = salt.to_read_sized();
//!
//! // generate the pw hash
//! let hash = <sodoken::BufWriteSized<32>>::new_no_lock();
//! sodoken::hash::argon2id::hash(
//!     hash.clone(),
//!     b"my-passphrase".to_vec(),
//!     salt.clone(),
//!     sodoken::hash::argon2id::OPSLIMIT_MIN,
//!     sodoken::hash::argon2id::MEMLIMIT_MIN,
//! ).await.unwrap();
//! let hash = hash.to_read_sized();
//! # }
//! ```

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
pub const OPSLIMIT_MIN: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN as u32;

/// argon2id pwhash interactive ops limit
pub const OPSLIMIT_INTERACTIVE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE as u32;

/// argon2id pwhash moderate ops limit
pub const OPSLIMIT_MODERATE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MODERATE as u32;

/// argon2id pwhash sensitive ops limit
pub const OPSLIMIT_SENSITIVE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE as u32;

/// argon2id pwhash max ops limit
pub const OPSLIMIT_MAX: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MAX as u32;

/// argon2id pwhash min mem limit
pub const MEMLIMIT_MIN: u32 =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MIN as u32;

/// argon2id pwhash interactive mem limit
pub const MEMLIMIT_INTERACTIVE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE as u32;

/// argon2id pwhash moderate mem limit
pub const MEMLIMIT_MODERATE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MODERATE as u32;

/// argon2id pwhash sensitive mem limit
pub const MEMLIMIT_SENSITIVE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE as u32;

/// argon2id13 password hashing scheme
pub async fn hash<H, P, S>(
    hash: H,
    passphrase: P,
    salt: S,
    ops_limit: u32,
    mem_limit: u32,
) -> SodokenResult<()>
where
    H: Into<BufWrite> + 'static + Send,
    P: Into<BufRead> + 'static + Send,
    S: Into<BufReadSized<SALTBYTES>> + 'static + Send,
{
    let hash = hash.into();
    let passphrase = passphrase.into();
    let salt = salt.into();
    tokio_exec_blocking(move || {
        // argon is designed to take a long time...
        // we don't want to hold these locks open for a long time,
        // so let's do some careful shuffling to only hold locks
        // on local single buf instances.

        let tmp_hash = BufWrite::new_mem_locked(hash.len())?;
        let tmp_passphrase = BufWrite::deep_clone_mem_locked(passphrase)?;
        let tmp_salt = BufWriteSized::deep_clone_no_lock(salt);

        let mut tmp_hash_lock = tmp_hash.write_lock();
        let tmp_passphrase_lock = tmp_passphrase.read_lock();
        let tmp_salt_lock = tmp_salt.read_lock_sized();

        safe::sodium::crypto_pwhash_argon2id(
            &mut tmp_hash_lock,
            &tmp_passphrase_lock,
            &tmp_salt_lock,
            ops_limit,
            mem_limit,
        )?;

        hash.write_lock().copy_from_slice(&tmp_hash_lock);

        Ok(())
    })
    .await?
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn argon2id() -> SodokenResult<()> {
        let pass = BufRead::new_no_lock(b"my passphrase");
        let salt: BufReadSized<{ hash::argon2id::SALTBYTES }> =
            BufReadSized::new_no_lock([0xdb; hash::argon2id::SALTBYTES]);
        let hash = BufWrite::new_no_lock(hash::argon2id::BYTES_MIN);
        hash::argon2id::hash(
            hash.clone(),
            pass,
            salt,
            hash::argon2id::OPSLIMIT_INTERACTIVE,
            hash::argon2id::MEMLIMIT_INTERACTIVE,
        )
        .await?;
        assert_eq!(
            "[236, 88, 226, 164, 99, 188, 201, 149, 83, 218, 26, 28, 193, 215, 226, 72]",
            format!("{:?}", &*hash.read_lock()),
        );
        Ok(())
    }
}
