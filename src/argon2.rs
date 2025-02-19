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
//! // generate salt
//! let salt = [0xdb; sodoken::argon2::ARGON2_ID_SALTBYTES];
//! // you should actually use a random salt:
//! // sodoken::random::randombytes_buf(&mut salt).unwrap();
//!
//! // generate the pw hash
//! let mut hash = <sodoken::SizedLockedArray<16>>::new().unwrap();
//! sodoken::argon2::blocking_argon2id(
//!     &mut *hash.lock(),
//!     b"my-passphrase",
//!     &salt,
//!     // don't use MIN except for CI/testing
//!     sodoken::argon2::ARGON2_ID_OPSLIMIT_MIN,
//!     // don't use MIN except for CI/testing
//!     sodoken::argon2::ARGON2_ID_MEMLIMIT_MIN,
//! ).unwrap();
//!
//! assert_eq!(&[207, 43, 248, 128], &hash.lock()[..4]);
//! ```

use crate::*;

/// minimum hash length for argon2id pwhash
pub const ARGON2_ID_BYTES_MIN: usize =
    libsodium_sys::crypto_pwhash_argon2id_BYTES_MIN as usize;

/// salt buffer length for argon2id pwhash
pub const ARGON2_ID_SALTBYTES: usize =
    libsodium_sys::crypto_pwhash_argon2id_SALTBYTES as usize;

/// minimum password length for argon2id pwhash
pub const ARGON2_ID_PASSWD_MIN: usize =
    libsodium_sys::crypto_pwhash_argon2id_PASSWD_MIN as usize;

/// maximum password length for argon2id pwhash
pub const ARGON2_ID_PASSWD_MAX: usize =
    libsodium_sys::crypto_pwhash_argon2id_PASSWD_MAX as usize;

/// argon2id pwhash min ops limit
pub const ARGON2_ID_OPSLIMIT_MIN: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN;

/// argon2id pwhash interactive ops limit
pub const ARGON2_ID_OPSLIMIT_INTERACTIVE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE;

/// argon2id pwhash moderate ops limit
pub const ARGON2_ID_OPSLIMIT_MODERATE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MODERATE;

/// argon2id pwhash sensitive ops limit
pub const ARGON2_ID_OPSLIMIT_SENSITIVE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE;

/// argon2id pwhash max ops limit
pub const ARGON2_ID_OPSLIMIT_MAX: u32 =
    libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MAX;

/// argon2id pwhash min mem limit
pub const ARGON2_ID_MEMLIMIT_MIN: u32 =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MIN;

/// argon2id pwhash interactive mem limit
pub const ARGON2_ID_MEMLIMIT_INTERACTIVE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE;

/// argon2id pwhash moderate mem limit
pub const ARGON2_ID_MEMLIMIT_MODERATE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MODERATE;

/// argon2id pwhash sensitive mem limit
pub const ARGON2_ID_MEMLIMIT_SENSITIVE: u32 =
    libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE;

/// Blocking argon2id13 password hashing scheme. Do not use directly in an
/// async context! Always use via your runtime's spawn_blocking or in
/// a separate thread.
pub fn blocking_argon2id(
    hash: &mut [u8],
    passphrase: &[u8],
    salt: &[u8; ARGON2_ID_SALTBYTES],
    ops_limit: u32,
    mem_limit: u32,
) -> Result<()> {
    if hash.len() < libsodium_sys::crypto_pwhash_argon2id_BYTES_MIN as usize {
        return Err(Error::other("bad hash size"));
    }

    if passphrase.len()
        < libsodium_sys::crypto_pwhash_argon2id_PASSWD_MIN as usize
        || passphrase.len()
            > libsodium_sys::crypto_pwhash_argon2id_PASSWD_MAX as usize
    {
        return Err(Error::other("bad passphrase size"));
    }

    // clippy doesn't like this:
    //if ops_limit < libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN
    //    || ops_limit > libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MAX
    if !(libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN
        ..=libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MAX)
        .contains(&ops_limit)
    {
        return Err(Error::other("bad ops limit"));
    }

    if mem_limit < libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MIN {
        return Err(Error::other("bad mem limit"));
    }

    // crypto_pwhash can error lots of bad sizes
    // we check sizes above for more detailed errors
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - sizes - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_pwhash(
            raw_ptr_char!(hash),
            hash.len() as libc::c_ulonglong,
            raw_ptr_ichar_immut!(passphrase),
            passphrase.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(salt),
            ops_limit as u64,
            mem_limit as usize,
            libsodium_sys::crypto_pwhash_argon2id_ALG_ARGON2ID13 as libc::c_int,
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}
