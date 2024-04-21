//! Libsodium crypto_kx types and functions.

use crate::*;

/// Byte length of kx public key.
pub const PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_kx_PUBLICKEYBYTES as usize;

/// Byte length of kx secret key.
pub const SECRETKEYBYTES: usize =
    libsodium_sys::crypto_kx_SECRETKEYBYTES as usize;

/// Byte length of kx session key.
pub const SESSIONKEYBYTES: usize =
    libsodium_sys::crypto_kx_SESSIONKEYBYTES as usize;

/// Generate session keys from the client perspective.
pub fn client_session_keys(
    rx: &mut [u8; SESSIONKEYBYTES],
    tx: &mut [u8; SESSIONKEYBYTES],
    client_pk: &[u8; PUBLICKEYBYTES],
    client_sk: &[u8; SECRETKEYBYTES],
    server_pk: &[u8; PUBLICKEYBYTES],
) -> Result<()> {
    // crypto_kx_client_session_keys mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_kx_client_session_keys(
            raw_ptr_char!(rx),
            raw_ptr_char!(tx),
            raw_ptr_char_immut!(client_pk),
            raw_ptr_char_immut!(client_sk),
            raw_ptr_char_immut!(server_pk),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}

/// Generate session keys from the server perspective.
pub fn server_session_keys(
    rx: &mut [u8; SESSIONKEYBYTES],
    tx: &mut [u8; SESSIONKEYBYTES],
    server_pk: &[u8; PUBLICKEYBYTES],
    server_sk: &[u8; SECRETKEYBYTES],
    client_pk: &[u8; PUBLICKEYBYTES],
) -> Result<()> {
    // crypto_kx_client_session_keys mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_kx_server_session_keys(
            raw_ptr_char!(rx),
            raw_ptr_char!(tx),
            raw_ptr_char_immut!(server_pk),
            raw_ptr_char_immut!(server_sk),
            raw_ptr_char_immut!(client_pk),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}
