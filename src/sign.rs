//! Libsodium crypto_sign types and functions.

use crate::*;

/// Length of seed.
pub const SEEDBYTES: usize = libsodium_sys::crypto_sign_SEEDBYTES as usize;

/// Length of public key.
pub const PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize;

/// Length of secret key.
pub const SECRETKEYBYTES: usize =
    libsodium_sys::crypto_sign_SECRETKEYBYTES as usize;

/// Length of signature.
pub const SIGNATUREBYTES: usize = libsodium_sys::crypto_sign_BYTES as usize;

/// Create an ed25519 signature keypair from a private seed.
pub fn seed_keypair(
    pub_key: &mut [u8; PUBLICKEYBYTES],
    sec_key: &mut [u8; SECRETKEYBYTES],
    seed: &[u8; SEEDBYTES],
) -> Result<()> {
    // crypto_sign_seed_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    //   - seed size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_sign_seed_keypair(
            raw_ptr_char!(pub_key),
            raw_ptr_char!(sec_key),
            raw_ptr_char_immut!(seed),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}

/// Create a new random ed25519 signature keypair.
pub fn keypair(
    pub_key: &mut [u8; PUBLICKEYBYTES],
    sec_key: &mut [u8; SECRETKEYBYTES],
) -> Result<()> {
    // crypto_sign_seed_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_sign_keypair(
            raw_ptr_char!(pub_key),
            raw_ptr_char!(sec_key),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}

/// Create a signature from a private key.
pub fn sign_detached(
    signature: &mut [u8; SIGNATUREBYTES],
    message: &[u8],
    sec_key: &[u8; SECRETKEYBYTES],
) -> Result<()> {
    // crypto_sign_detached mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - signature size - checked above
    //   - sec_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_sign_detached(
            raw_ptr_char!(signature),
            std::ptr::null_mut(),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(sec_key),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}

/// Verify a signature against a public key.
pub fn verify_detached(
    signature: &[u8; SIGNATUREBYTES],
    message: &[u8],
    pub_key: &[u8; PUBLICKEYBYTES],
) -> bool {
    // crypto_sign_verify_detached mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - signature size - checked above
    //   - pub_key size - checked above
    crate::sodium_init();
    unsafe {
        libsodium_sys::crypto_sign_verify_detached(
            raw_ptr_char_immut!(signature),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(pub_key),
        ) == 0_i32
    }
}

/// Convert a signing ed25519 public key into an encryption x25519 public key.
/// Please understand the downsides of this function before making use of it.
/// <https://doc.libsodium.org/advanced/ed25519-curve25519>
pub fn pk_to_curve25519(
    x25519_pk: &mut [u8; libsodium_sys::crypto_scalarmult_curve25519_BYTES
             as usize],
    ed25519_pk: &[u8; libsodium_sys::crypto_sign_ed25519_PUBLICKEYBYTES
         as usize],
) -> Result<()> {
    // ed25519_pk_to_curve25519 mainly fails from sizes checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - signature size - checked above
    //   - pub_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(
            raw_ptr_char!(x25519_pk),
            raw_ptr_char_immut!(ed25519_pk),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}

/// Convert a signing ed25519 secret key into an encryption x25519 secret key.
/// Please understand the downsides of this function before making use of it.
/// <https://doc.libsodium.org/advanced/ed25519-curve25519>
pub fn sk_to_curve25519(
    x25519_sk: &mut [u8; libsodium_sys::crypto_scalarmult_curve25519_BYTES
             as usize],
    ed25519_sk: &[u8; libsodium_sys::crypto_sign_ed25519_SECRETKEYBYTES
         as usize],
) -> Result<()> {
    // ed25519_sk_to_curve25519 mainly fails from sizes checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - signature size - checked above
    //   - pub_key size - checked above
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_sign_ed25519_sk_to_curve25519(
            raw_ptr_char!(x25519_sk),
            raw_ptr_char_immut!(ed25519_sk),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}
