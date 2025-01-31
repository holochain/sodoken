//! Modules related to cryptographic box encryption / decryption.
//!
//! #### Example Sealed Box Encryption / Decryption
//!
//! ```
//! // recipient has a keypair
//! let mut pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
//! let mut sk = sodoken::LockedArray::new().unwrap();
//! sodoken::crypto_box::xsalsa_keypair(&mut pk, &mut sk.lock()).unwrap();
//!
//! // sender encrypts a message using receiver pub key
//! let msg = b"test-message".to_vec();
//! let mut cipher = vec![0; msg.len() + sodoken::crypto_box::XSALSA_SEALBYTES];
//! sodoken::crypto_box::xsalsa_seal(&mut cipher, &msg, &pk).unwrap();
//!
//! // recipient can decrypt the message
//! let mut msg = vec![0; cipher.len() - sodoken::crypto_box::XSALSA_SEALBYTES];
//! sodoken::crypto_box::xsalsa_seal_open(&mut msg, &cipher, &pk, &sk.lock())
//!     .unwrap();
//!
//! assert_eq!(
//!     "test-message",
//!     String::from_utf8_lossy(&msg),
//! );
//! ```
//!
//! #### Example Box Encryption / Decryption
//!
//! ```
//! // recipient has a keypair
//! let mut r_pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
//! let mut r_sk = sodoken::LockedArray::new().unwrap();
//! sodoken::crypto_box::xsalsa_keypair(&mut r_pk, &mut r_sk.lock()).unwrap();
//!
//! // sender has a keypair
//! let mut s_pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
//! let mut s_sk = sodoken::LockedArray::new().unwrap();
//! sodoken::crypto_box::xsalsa_keypair(&mut s_pk, &mut s_sk.lock()).unwrap();
//!
//! // sender encrypts a message
//! let msg = b"test-message".to_vec();
//! let mut nonce = [0; sodoken::crypto_box::XSALSA_NONCEBYTES];
//! sodoken::random::randombytes_buf(&mut nonce).unwrap();
//! let mut cipher = vec![0; msg.len() + sodoken::crypto_box::XSALSA_MACBYTES];
//! sodoken::crypto_box::xsalsa_easy(
//!     &mut cipher,
//!     &msg,
//!     &nonce,
//!     &r_pk,
//!     &s_sk.lock(),
//! ).unwrap();
//!
//! // receiver decrypts the message
//! let msg_len = cipher.len() - sodoken::crypto_box::XSALSA_MACBYTES;
//! let mut msg = vec![0; msg_len];
//! sodoken::crypto_box::xsalsa_open_easy(
//!     &mut msg,
//!     &cipher,
//!     &nonce,
//!     &s_pk,
//!     &r_sk.lock(),
//! ).unwrap();
//!
//! assert_eq!(
//!     "test-message",
//!     String::from_utf8_lossy(&msg),
//! );
//! ```

use crate::*;

/// length of box seed
pub const XSALSA_SEEDBYTES: usize =
    libsodium_sys::crypto_box_SEEDBYTES as usize;

/// length of box public key
pub const XSALSA_PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_box_PUBLICKEYBYTES as usize;

/// length of box secret key
pub const XSALSA_SECRETKEYBYTES: usize =
    libsodium_sys::crypto_box_SECRETKEYBYTES as usize;

/// length of box mac
pub const XSALSA_MACBYTES: usize = libsodium_sys::crypto_box_MACBYTES as usize;

/// length of box nonce
pub const XSALSA_NONCEBYTES: usize =
    libsodium_sys::crypto_box_NONCEBYTES as usize;

/// sealed box extra bytes
pub const XSALSA_SEALBYTES: usize =
    libsodium_sys::crypto_box_SEALBYTES as usize;

/// create a box curve25519xsalsa20poly1305 keypair from a private seed
pub fn xsalsa_seed_keypair(
    pub_key: &mut [u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
    sec_key: &mut [u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize],
    seed: &[u8; libsodium_sys::crypto_box_SEEDBYTES as usize],
) -> Result<()> {
    // crypto_box_seed_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    //   - seed size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_box_seed_keypair(
            raw_ptr_char!(pub_key),
            raw_ptr_char!(sec_key),
            raw_ptr_char_immut!(seed),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(Error::other("internal"))
    }
}

/// create a box curve25519xsalsa20poly1305 keypair from entropy
pub fn xsalsa_keypair(
    pub_key: &mut [u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
    sec_key: &mut [u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize],
) -> Result<()> {
    // crypto_box_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_box_keypair(
            raw_ptr_char!(pub_key),
            raw_ptr_char!(sec_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(Error::other("internal"))
    }
}

/// encrypt data with box_curve25519xsalsa20poly1305_easy
pub fn xsalsa_easy(
    cipher: &mut [u8],
    message: &[u8],
    nonce: &[u8; libsodium_sys::crypto_box_NONCEBYTES as usize],
    dest_pub_key: &[u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
    src_sec_key: &[u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize],
) -> Result<()> {
    let cipher_len =
        message.len() + libsodium_sys::crypto_box_MACBYTES as usize;

    if cipher.len() != cipher_len {
        return Err(Error::other("bad cipher size"));
    }

    // crypto_box_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - cipher size - calculated above
    //   - nonce size - checked above
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    crate::sodium_init();
    #[allow(clippy::uninit_vec)]
    unsafe {
        if libsodium_sys::crypto_box_easy(
            raw_ptr_char!(cipher),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(dest_pub_key),
            raw_ptr_char_immut!(src_sec_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(Error::other("internal"))
    }
}

/// decrypt data with box_curve25519xsalsa20poly1305_open_easy
pub fn xsalsa_open_easy(
    message: &mut [u8],
    cipher: &[u8],
    nonce: &[u8; libsodium_sys::crypto_box_NONCEBYTES as usize],
    src_pub_key: &[u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
    dest_sec_key: &[u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize],
) -> Result<()> {
    let msg_len = cipher.len() - libsodium_sys::crypto_box_MACBYTES as usize;

    if message.len() != msg_len {
        return Err(Error::other("bad message size"));
    }

    // crypto_box_open_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - message size - checked above
    //   - cipher size - checked above
    //   - nonce size - checked above
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_box_open_easy(
            raw_ptr_char!(message),
            raw_ptr_char_immut!(cipher),
            cipher.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(src_pub_key),
            raw_ptr_char_immut!(dest_sec_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(Error::other("internal"))
    }
}

/// seal (encrypt) a message with an ephemeral key that can't even be decrypted
/// by this sender.
pub fn xsalsa_seal(
    cipher: &mut [u8],
    message: &[u8],
    dest_pub_key: &[u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
) -> Result<()> {
    let c_len = message.len() + libsodium_sys::crypto_box_SEALBYTES as usize;

    if cipher.len() != c_len {
        return Err(Error::other("bad cipher size"));
    }

    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - message size - checked above
    //   - cipher size - checked above
    //   - pub_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_box_seal(
            raw_ptr_char!(cipher),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(dest_pub_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(Error::other("internal"))
    }
}

/// open (decrypt) a sealed message.
pub fn xsalsa_seal_open(
    message: &mut [u8],
    cipher: &[u8],
    pub_key: &[u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
    sec_key: &[u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize],
) -> Result<()> {
    let m_len = cipher.len() - libsodium_sys::crypto_box_SEALBYTES as usize;

    if message.len() != m_len {
        return Err(Error::other("bad message size"));
    }

    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - message size - checked above
    //   - cipher size - checked above
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_box_seal_open(
            raw_ptr_char!(message),
            raw_ptr_char_immut!(cipher),
            cipher.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(pub_key),
            raw_ptr_char_immut!(sec_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(Error::other("internal"))
    }
}

#[cfg(test)]
mod tests {
    // make sure the default `crypto_box_*` are xsalsa
    // crypto_box_curve25519xsalsa20poly1305_* doesn't include _easy...
    #[test]
    fn test_crypto_box_assert_default_salsa() {
        let default_box_primitive = unsafe {
            let c =
                std::ffi::CStr::from_ptr(libsodium_sys::crypto_box_primitive());
            c.to_str().unwrap()
        };
        assert_eq!("curve25519xsalsa20poly1305", default_box_primitive);
    }
}
