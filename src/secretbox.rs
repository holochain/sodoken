//! Modules related to cryptographic secretbox encryption / decryption.
//!
//! #### Example SecretBox Encryption / Decryption
//!
//! ```
//! // generate a shared secret
//! let mut s_key = sodoken::LockedArray::new().unwrap();
//! sodoken::random::randombytes_buf(&mut *s_key.lock()).unwrap();
//!
//! // sender encrypts a message
//! let msg = b"test-message".to_vec();
//! let mut nonce = [0; sodoken::secretbox::XSALSA_NONCEBYTES];
//! sodoken::random::randombytes_buf(&mut nonce).unwrap();
//! let mut cipher = vec![0; msg.len() + sodoken::secretbox::XSALSA_MACBYTES];
//! sodoken::secretbox::xsalsa_easy(
//!     &mut cipher,
//!     &nonce,
//!     &msg,
//!     &s_key.lock(),
//! ).unwrap();
//!
//! // receiver decrypts the message
//! let msg_len = cipher.len() - sodoken::secretbox::XSALSA_MACBYTES;
//! let mut msg = vec![0; msg_len];
//! sodoken::secretbox::xsalsa_open_easy(
//!     &mut msg,
//!     &cipher,
//!     &nonce,
//!     &s_key.lock(),
//! ).unwrap();
//!
//! assert_eq!(
//!     "test-message",
//!     String::from_utf8_lossy(&msg),
//! );
//! ```

use crate::*;

/// length of secretbox key
pub const XSALSA_KEYBYTES: usize =
    libsodium_sys::crypto_secretbox_xsalsa20poly1305_KEYBYTES as usize;

/// length of secretbox nonce
pub const XSALSA_NONCEBYTES: usize =
    libsodium_sys::crypto_secretbox_xsalsa20poly1305_NONCEBYTES as usize;

/// length of secretbox mac
pub const XSALSA_MACBYTES: usize =
    libsodium_sys::crypto_secretbox_xsalsa20poly1305_MACBYTES as usize;

/// encrypt data with crytpo_secretbox_xsalsa20poly1305_easy
pub fn xsalsa_easy(
    cipher: &mut [u8],
    nonce: &[u8; libsodium_sys::crypto_secretbox_xsalsa20poly1305_NONCEBYTES
         as usize],
    message: &[u8],
    shared_key: &[u8;
         libsodium_sys::crypto_secretbox_xsalsa20poly1305_KEYBYTES
             as usize],
) -> Result<()> {
    let cipher_len = message.len()
        + libsodium_sys::crypto_secretbox_xsalsa20poly1305_MACBYTES as usize;

    if cipher.len() != cipher_len {
        return Err(Error::other("bad cipher size"));
    }

    // crypto_secretbox_xsalsa20poly1305_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - cipher size - calculated above
    //   - nonce size - checked above
    //   - shared_key size - checked above
    crate::sodium_init();
    #[allow(clippy::uninit_vec)]
    unsafe {
        if libsodium_sys::crypto_secretbox_easy(
            raw_ptr_char!(cipher),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(shared_key),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}

/// decrypt data with crypto_secretbox_xsalsa20poly1305_open_easy
pub fn xsalsa_open_easy(
    message: &mut [u8],
    cipher: &[u8],
    nonce: &[u8; libsodium_sys::crypto_secretbox_xsalsa20poly1305_NONCEBYTES
         as usize],
    shared_key: &[u8;
         libsodium_sys::crypto_secretbox_xsalsa20poly1305_KEYBYTES
             as usize],
) -> Result<()> {
    let msg_len = cipher.len()
        - libsodium_sys::crypto_secretbox_xsalsa20poly1305_MACBYTES as usize;

    if message.len() != msg_len {
        return Err(Error::other("bad message size"));
    }

    // crypto_secretbox_xsalsa20poly1305_open_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - message size - checked above
    //   - cipher size - checked above
    //   - nonce size - checked above
    //   - shared_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_secretbox_open_easy(
            raw_ptr_char!(message),
            raw_ptr_char_immut!(cipher),
            cipher.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(shared_key),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}

#[cfg(test)]
mod tests {
    // make sure the default `crypto_secretbox_*` are xsalsa
    // crypto_secretbox_xsalsa20poly1305_* doesn't include _easy...
    #[test]
    fn test_crypto_secretbox_assert_default_salsa() {
        let default_box_primitive = unsafe {
            let c = std::ffi::CStr::from_ptr(
                libsodium_sys::crypto_secretbox_primitive(),
            );
            c.to_str().unwrap()
        };
        assert_eq!("xsalsa20poly1305", default_box_primitive);
    }
}
