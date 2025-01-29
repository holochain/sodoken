//! Libsodium crypto_kx types and functions.

use crate::*;

/// Byte length of kdf "context" parameter.
pub const CONTEXTBYTES: usize = libsodium_sys::crypto_kdf_CONTEXTBYTES as usize;

/// Byte length of kdf "parent" key.
pub const KEYBYTES: usize = libsodium_sys::crypto_kdf_KEYBYTES as usize;

/// Derive a subkey from a parent key.
pub fn derive_from_key(
    sub_key: &mut [u8],
    subkey_id: u64,
    ctx: &[u8; CONTEXTBYTES],
    parent_key: &[u8; KEYBYTES],
) -> Result<()> {
    if sub_key.len() < libsodium_sys::crypto_kdf_BYTES_MIN as usize
        || sub_key.len() > libsodium_sys::crypto_kdf_BYTES_MAX as usize
    {
        return Err(Error::other("bad key size"));
    }

    // crypto_sign_seed_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - sub_key size - checked above
    //   - parent_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_kdf_derive_from_key(
            raw_ptr_char!(sub_key),
            sub_key.len(),
            subkey_id,
            raw_ptr_ichar_immut!(ctx),
            raw_ptr_char_immut!(parent_key),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}
