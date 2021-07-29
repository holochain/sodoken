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
    salt: &[u8; libsodium_sys::crypto_pwhash_argon2id_SALTBYTES as usize],
    ops_limit: u64,
    mem_limit: usize,
) -> SodokenResult<()> {
    if hash.len() < libsodium_sys::crypto_pwhash_argon2id_BYTES_MIN as usize {
        return Err(SodokenError::BadHashSize);
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
    pub_key: &mut [u8; libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize],
    sec_key: &mut [u8; libsodium_sys::crypto_sign_SECRETKEYBYTES as usize],
    seed: &[u8; libsodium_sys::crypto_sign_SEEDBYTES as usize],
) -> SodokenResult<()> {
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
    pub_key: &mut [u8; libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize],
    sec_key: &mut [u8; libsodium_sys::crypto_sign_SECRETKEYBYTES as usize],
) -> SodokenResult<()> {
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
    signature: &mut [u8; libsodium_sys::crypto_sign_BYTES as usize],
    message: &[u8],
    sec_key: &[u8; libsodium_sys::crypto_sign_SECRETKEYBYTES as usize],
) -> SodokenResult<()> {
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
    signature: &[u8; libsodium_sys::crypto_sign_BYTES as usize],
    message: &[u8],
    pub_key: &[u8; libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize],
) -> SodokenResult<bool> {
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

pub(crate) fn crypto_box_curve25519xchacha20poly1305_seed_keypair(
    pub_key: &mut [u8; libsodium_sys::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize],
    sec_key: &mut [u8; libsodium_sys::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize],
    seed: &[u8;
         libsodium_sys::crypto_box_curve25519xchacha20poly1305_SEEDBYTES
             as usize],
) -> SodokenResult<()> {
    // crypto_box_curve25519xchacha20poly1305_seed_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    //   - seed size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_box_curve25519xchacha20poly1305_seed_keypair(
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

pub(crate) fn crypto_box_curve25519xchacha20poly1305_keypair(
    pub_key: &mut [u8; libsodium_sys::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize],
    sec_key: &mut [u8; libsodium_sys::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize],
) -> SodokenResult<()> {
    // crypto_box_keypair mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_box_curve25519xchacha20poly1305_keypair(
            raw_ptr_char!(pub_key),
            raw_ptr_char!(sec_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(SodokenError::InternalSodium)
    }
}

pub(crate) fn crypto_box_curve25519xchacha20poly1305_easy(
    nonce: &[u8;
         libsodium_sys::crypto_box_curve25519xchacha20poly1305_NONCEBYTES
             as usize],
    message: &[u8],
    dest_pub_key: &[u8;
         libsodium_sys::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
             as usize],
    src_sec_key: &[u8;
         libsodium_sys::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES
             as usize],
) -> SodokenResult<Vec<u8>> {
    let cipher_len = message.len()
        + libsodium_sys::crypto_box_curve25519xchacha20poly1305_MACBYTES
            as usize;

    // crypto_box_curve25519xchacha20poly1305_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - cipher size - calculated above
    //   - nonce size - checked above
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        let mut cipher = Vec::with_capacity(cipher_len);
        cipher.set_len(cipher_len);

        if libsodium_sys::crypto_box_curve25519xchacha20poly1305_easy(
            raw_ptr_char!(cipher),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(dest_pub_key),
            raw_ptr_char_immut!(src_sec_key),
        ) == 0_i32
        {
            return Ok(cipher);
        }
        Err(SodokenError::InternalSodium)
    }
}

pub(crate) fn crypto_box_curve25519xchacha20poly1305_open_easy(
    nonce: &[u8;
         libsodium_sys::crypto_box_curve25519xchacha20poly1305_NONCEBYTES
             as usize],
    message: &mut [u8],
    cipher: &[u8],
    src_pub_key: &[u8;
         libsodium_sys::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
             as usize],
    dest_sec_key: &[u8;
         libsodium_sys::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES
             as usize],
) -> SodokenResult<()> {
    let msg_len = cipher.len()
        - libsodium_sys::crypto_box_curve25519xchacha20poly1305_MACBYTES
            as usize;

    if message.len() != msg_len {
        return Err(SodokenError::BadMessageSize);
    }

    // crypto_box_curve25519xchacha20poly1305_open_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - message size - checked above
    //   - cipher size - checked above
    //   - nonce size - checked above
    //   - pub_key size - checked above
    //   - sec_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_box_curve25519xchacha20poly1305_open_easy(
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
        Err(SodokenError::InternalSodium)
    }
}

use crate::secretstream_xchacha20poly1305::SecretStreamTag;

pub(crate) fn crypto_secretstream_xchacha20poly1305_init_push(
    key: &[u8; libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES
         as usize],
    header: &mut BufExtend,
) -> SodokenResult<libsodium_sys::crypto_secretstream_xchacha20poly1305_state> {
    let mut state =
        libsodium_sys::crypto_secretstream_xchacha20poly1305_state {
            k: Default::default(),
            nonce: Default::default(),
            _pad: Default::default(),
        };

    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - sizes enforced by type system
    assert!(*SODIUM_INIT);
    let res = unsafe {
        let mut header = header.extend_lock();
        let header = header.unsafe_extend_mut(
            libsodium_sys::crypto_secretstream_xchacha20poly1305_HEADERBYTES
                as usize,
        )?;
        libsodium_sys::crypto_secretstream_xchacha20poly1305_init_push(
            &mut state,
            raw_ptr_char!(header),
            raw_ptr_char_immut!(key),
        )
    };

    if res == 0_i32 {
        return Ok(state);
    }

    Err(SodokenError::InternalSodium)
}

pub(crate) fn crypto_secretstream_xchacha20poly1305_push(
    state: &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
    message: &[u8],
    adata: Option<&[u8]>,
    tag: SecretStreamTag,
    cipher: &mut BufExtend,
) -> SodokenResult<()> {
    let (adata_len, adata) = match adata {
        Some(adata) => {
            (adata.len() as libc::c_ulonglong, raw_ptr_char_immut!(adata))
        }
        None => (0, std::ptr::null()),
    };

    let cipher_len = message.len()
        + libsodium_sys::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - sizes enforced by type system
    assert!(*SODIUM_INIT);
    let res = unsafe {
        let mut cipher = cipher.extend_lock();
        let cipher = cipher.unsafe_extend_mut(cipher_len)?;
        let message_len = message.len() as libc::c_ulonglong;
        libsodium_sys::crypto_secretstream_xchacha20poly1305_push(
            state,
            raw_ptr_char!(cipher),
            // cipher len is deterministic, we don't need it reported
            std::ptr::null_mut(),
            raw_ptr_char_immut!(message),
            message_len,
            adata,
            adata_len,
            tag as u8,
        )
    };

    if res == 0_i32 {
        return Ok(());
    }

    Err(SodokenError::InternalSodium)
}

pub(crate) fn crypto_secretstream_xchacha20poly1305_init_pull(
    header: &[u8;
         libsodium_sys::crypto_secretstream_xchacha20poly1305_HEADERBYTES
             as usize],
    key: &[u8; libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES
         as usize],
) -> SodokenResult<libsodium_sys::crypto_secretstream_xchacha20poly1305_state> {
    let mut state =
        libsodium_sys::crypto_secretstream_xchacha20poly1305_state {
            k: Default::default(),
            nonce: Default::default(),
            _pad: Default::default(),
        };

    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - sizes enforced by type system
    assert!(*SODIUM_INIT);
    let res = unsafe {
        libsodium_sys::crypto_secretstream_xchacha20poly1305_init_pull(
            &mut state,
            raw_ptr_char_immut!(header),
            raw_ptr_char_immut!(key),
        )
    };

    if res == 0_i32 {
        return Ok(state);
    }

    Err(SodokenError::InternalSodium)
}

pub(crate) fn crypto_secretstream_xchacha20poly1305_pull(
    state: &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
    message: &mut BufExtend,
    cipher: &[u8],
    adata: Option<&[u8]>,
) -> SodokenResult<SecretStreamTag> {
    let msg_len = cipher.len()
        - libsodium_sys::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

    let mut tag = 0;

    let (adata_len, adata) = match adata {
        Some(adata) => {
            (adata.len() as libc::c_ulonglong, raw_ptr_char_immut!(adata))
        }
        None => (0, std::ptr::null()),
    };

    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - sizes enforced by type system + msg_len calc above
    assert!(*SODIUM_INIT);
    let res = unsafe {
        let mut message = message.extend_lock();
        let message = message.unsafe_extend_mut(msg_len)?;
        let cipher_len = cipher.len() as libc::c_ulonglong;
        libsodium_sys::crypto_secretstream_xchacha20poly1305_pull(
            state,
            raw_ptr_char!(message),
            // message len is deterministic, we don't need it reported
            std::ptr::null_mut(),
            &mut tag,
            raw_ptr_char_immut!(cipher),
            cipher_len,
            adata,
            adata_len,
        )
    };

    if res == 0_i32 {
        let tag = match tag as u32 {
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE => SecretStreamTag::Message,
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_PUSH => SecretStreamTag::Push,
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_REKEY => SecretStreamTag::Rekey,
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL => SecretStreamTag::Final,
            _ => return Err(SodokenError::InternalSodium),
        };

        return Ok(tag);
    }

    Err(SodokenError::InternalSodium)
}

pub(crate) fn crypto_secretstream_xchacha20poly1305_rekey(
    state: &mut libsodium_sys::crypto_secretstream_xchacha20poly1305_state,
) {
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    assert!(*SODIUM_INIT);
    unsafe {
        libsodium_sys::crypto_secretstream_xchacha20poly1305_rekey(state);
    }
}
