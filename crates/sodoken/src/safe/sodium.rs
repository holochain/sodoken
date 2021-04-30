//! None of the unsafe blocks in here interdepend.
//! The invariant lists for each unsafe block can be evaluated separately.

use crate::*;

/// make invoking ffi functions more readable
macro_rules! raw_ptr_void {
    ($name: ident) => {
        $name.as_mut_ptr() as *mut libc::c_void
    };
}

/// make invoking ffi functions more readable
macro_rules! raw_ptr_char {
    ($name: ident) => {
        $name.as_mut_ptr() as *mut libc::c_uchar
    };
}

/// make invoking ffi functions more readable
macro_rules! raw_ptr_char_immut {
    ($name: ident) => {
        $name.as_ptr() as *const libc::c_uchar
    };
}

/// make invoking ffi functions more readable
macro_rules! raw_ptr_ichar_immut {
    ($name: ident) => {
        $name.as_ptr() as *const libc::c_char
    };
}

pub(crate) fn sodium_init() -> SodokenResult<()> {
    // sodium_init will return < 0 if an allocation / threading error occurs
    // it will return > 0 if sodium_init() was already called,
    // but this is ok/noop
    //
    // NO INVARIANTS
    unsafe {
        if libsodium_sys::sodium_init() > -1 {
            return Ok(());
        }
    }
    Err(SodokenError::InternalSodium)
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn randombytes_buf(buf: &mut [u8]) -> SodokenResult<()> {
    // randombytes_buf doesn't return anything and only acts on an already
    // allocated buffer - there are no error conditions possible here.
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    assert!(*SODIUM_INIT);
    unsafe {
        libsodium_sys::randombytes_buf(raw_ptr_void!(buf), buf.len());
        Ok(())
    }
}

pub(crate) fn crypto_generichash(
    hash: &mut [u8],
    message: &[u8],
    key: Option<&[u8]>,
) -> SodokenResult<()> {
    if hash.len() < libsodium_sys::crypto_generichash_BYTES_MIN as usize
        || hash.len() > libsodium_sys::crypto_generichash_BYTES_MAX as usize
    {
        return Err(SodokenError::BadHashSize);
    }

    let (key_len, key) = match key {
        Some(key) => {
            if key.len()
                < libsodium_sys::crypto_generichash_KEYBYTES_MIN as usize
                || key.len()
                    > libsodium_sys::crypto_generichash_KEYBYTES_MAX as usize
            {
                return Err(SodokenError::BadKeySize);
            }
            (key.len(), raw_ptr_char_immut!(key))
        }
        None => (0, std::ptr::null()),
    };

    // crypto_generichash can error on bad hash size / or bad key size
    // it can handle message sizes up to the max c_ulonglong.
    // we check sizes above for more detailed errors
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - hash size - checked above
    //   - key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_generichash(
            raw_ptr_char!(hash),
            hash.len(),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            key,
            key_len,
        ) == 0_i32
        {
            return Ok(());
        }
        Err(SodokenError::InternalSodium)
    }
}

pub(crate) fn crypto_pwhash_argon2id(
    hash: &mut [u8],
    passphrase: &[u8],
    salt: &[u8],
    ops_limit: u64,
    mem_limit: usize,
) -> SodokenResult<()> {
    if hash.len() < libsodium_sys::crypto_pwhash_argon2id_BYTES_MIN as usize {
        return Err(SodokenError::BadHashSize);
    }

    if salt.len() != libsodium_sys::crypto_pwhash_argon2id_SALTBYTES as usize {
        return Err(SodokenError::BadSaltSize);
    }

    if passphrase.len()
        < libsodium_sys::crypto_pwhash_argon2id_PASSWD_MIN as usize
        || passphrase.len()
            > libsodium_sys::crypto_pwhash_argon2id_PASSWD_MAX as usize
    {
        return Err(SodokenError::BadPassphraseSize);
    }

    if ops_limit < libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN as u64
        || ops_limit > libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MAX as u64
    {
        return Err(SodokenError::BadOpsLimit);
    }

    if mem_limit < libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MIN as usize {
        return Err(SodokenError::BadMemLimit);
    }

    // crypto_pwhash can error lots of bad sizes
    // we check sizes above for more detailed errors
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - sizes - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_pwhash(
            raw_ptr_char!(hash),
            hash.len() as libc::c_ulonglong,
            raw_ptr_ichar_immut!(passphrase),
            passphrase.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(salt),
            ops_limit,
            mem_limit,
            libsodium_sys::crypto_pwhash_argon2id_ALG_ARGON2ID13 as libc::c_int,
        ) == 0_i32
        {
            return Ok(());
        }
        Err(SodokenError::InternalSodium)
    }
}

pub(crate) fn crypto_sign_seed_keypair(
    pub_key: &mut [u8],
    sec_key: &mut [u8],
    seed: &[u8],
) -> SodokenResult<()> {
    if pub_key.len() != libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize {
        return Err(SodokenError::BadPublicKeySize);
    }

    if sec_key.len() != libsodium_sys::crypto_sign_SECRETKEYBYTES as usize {
        return Err(SodokenError::BadSecretKeySize);
    }

    if seed.len() != libsodium_sys::crypto_sign_SEEDBYTES as usize {
        return Err(SodokenError::BadSeedSize);
    }

    // crypto_sign_seed_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    //   - seed size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_sign_seed_keypair(
            raw_ptr_char!(pub_key),
            raw_ptr_char!(sec_key),
            raw_ptr_char_immut!(seed),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(SodokenError::InternalSodium)
    }
}

pub(crate) fn crypto_sign_keypair(
    pub_key: &mut [u8],
    sec_key: &mut [u8],
) -> SodokenResult<()> {
    if pub_key.len() != libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize {
        return Err(SodokenError::BadPublicKeySize);
    }

    if sec_key.len() != libsodium_sys::crypto_sign_SECRETKEYBYTES as usize {
        return Err(SodokenError::BadSecretKeySize);
    }

    // crypto_sign_seed_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_sign_keypair(
            raw_ptr_char!(pub_key),
            raw_ptr_char!(sec_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(SodokenError::InternalSodium)
    }
}

pub(crate) fn crypto_sign_detached(
    signature: &mut [u8],
    message: &[u8],
    sec_key: &[u8],
) -> SodokenResult<()> {
    if signature.len() != libsodium_sys::crypto_sign_BYTES as usize {
        return Err(SodokenError::BadSignatureSize);
    }

    if sec_key.len() != libsodium_sys::crypto_sign_SECRETKEYBYTES as usize {
        return Err(SodokenError::BadSecretKeySize);
    }

    // crypto_sign_detached mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - signature size - checked above
    //   - sec_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_sign_detached(
            raw_ptr_char!(signature),
            std::ptr::null_mut(),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(sec_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(SodokenError::InternalSodium)
    }
}

pub(crate) fn crypto_sign_verify_detached(
    signature: &[u8],
    message: &[u8],
    pub_key: &[u8],
) -> SodokenResult<bool> {
    if signature.len() != libsodium_sys::crypto_sign_BYTES as usize {
        return Err(SodokenError::BadSignatureSize);
    }

    if pub_key.len() != libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize {
        return Err(SodokenError::BadPublicKeySize);
    }

    // crypto_sign_verify_detached mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - signature size - checked above
    //   - pub_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        Ok(libsodium_sys::crypto_sign_verify_detached(
            raw_ptr_char_immut!(signature),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(pub_key),
        ) == 0_i32)
    }
}
