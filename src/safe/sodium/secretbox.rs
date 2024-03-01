// if the api fails, we don't return the uninitialized bytes
#![allow(clippy::uninit_vec)]

use super::*;

// -- xchacha20poly1305 -- //

pub(crate) fn crypto_secretbox_xchacha20poly1305_easy(
    nonce: &[u8; libsodium_sys::crypto_secretbox_xchacha20poly1305_NONCEBYTES
         as usize],
    message: &[u8],
    shared_key: &[u8;
         libsodium_sys::crypto_secretbox_xchacha20poly1305_KEYBYTES
             as usize],
) -> SodokenResult<Vec<u8>> {
    let cipher_len = message.len()
        + libsodium_sys::crypto_secretbox_xchacha20poly1305_MACBYTES as usize;

    // crypto_secretbox_xchacha20poly1305_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - cipher size - calculated above
    //   - nonce size - checked above
    //   - shared_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        let mut cipher = Vec::with_capacity(cipher_len);
        cipher.set_len(cipher_len);

        if libsodium_sys::crypto_secretbox_xchacha20poly1305_easy(
            raw_ptr_char!(cipher),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(shared_key),
        ) == 0_i32
        {
            return Ok(cipher);
        }
        Err(SodokenErrKind::InternalSodium.into())
    }
}

pub(crate) fn crypto_secretbox_xchacha20poly1305_open_easy(
    nonce: &[u8; libsodium_sys::crypto_secretbox_xchacha20poly1305_NONCEBYTES
         as usize],
    message: &mut [u8],
    cipher: &[u8],
    shared_key: &[u8;
         libsodium_sys::crypto_secretbox_xchacha20poly1305_KEYBYTES
             as usize],
) -> SodokenResult<()> {
    let msg_len = cipher.len()
        - libsodium_sys::crypto_secretbox_xchacha20poly1305_MACBYTES as usize;

    if message.len() != msg_len {
        return Err(SodokenErrKind::BadMessageSize.into());
    }

    // crypto_secretbox_xchacha20poly1305_open_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - message size - checked above
    //   - cipher size - checked above
    //   - nonce size - checked above
    //   - shared_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_secretbox_xchacha20poly1305_open_easy(
            raw_ptr_char!(message),
            raw_ptr_char_immut!(cipher),
            cipher.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(shared_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(SodokenErrKind::InternalSodium.into())
    }
}

// -- xsalsa20poly1305 -- //

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

pub(crate) fn crypto_secretbox_xsalsa20poly1305_easy(
    nonce: &[u8; libsodium_sys::crypto_secretbox_xsalsa20poly1305_NONCEBYTES
         as usize],
    message: &[u8],
    shared_key: &[u8;
         libsodium_sys::crypto_secretbox_xsalsa20poly1305_KEYBYTES
             as usize],
) -> SodokenResult<Vec<u8>> {
    let cipher_len = message.len()
        + libsodium_sys::crypto_secretbox_xsalsa20poly1305_MACBYTES as usize;

    // crypto_secretbox_xsalsa20poly1305_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - cipher size - calculated above
    //   - nonce size - checked above
    //   - shared_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        let mut cipher = Vec::with_capacity(cipher_len);
        cipher.set_len(cipher_len);

        if libsodium_sys::crypto_secretbox_easy(
            raw_ptr_char!(cipher),
            raw_ptr_char_immut!(message),
            message.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(shared_key),
        ) == 0_i32
        {
            return Ok(cipher);
        }
        Err(SodokenErrKind::InternalSodium.into())
    }
}

pub(crate) fn crypto_secretbox_xsalsa20poly1305_open_easy(
    nonce: &[u8; libsodium_sys::crypto_secretbox_xsalsa20poly1305_NONCEBYTES
         as usize],
    message: &mut [u8],
    cipher: &[u8],
    shared_key: &[u8;
         libsodium_sys::crypto_secretbox_xsalsa20poly1305_KEYBYTES
             as usize],
) -> SodokenResult<()> {
    let msg_len = cipher.len()
        - libsodium_sys::crypto_secretbox_xsalsa20poly1305_MACBYTES as usize;

    if message.len() != msg_len {
        return Err(SodokenErrKind::BadMessageSize.into());
    }

    // crypto_secretbox_xsalsa20poly1305_open_easy mainly failes from sized checked above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by SODIUM_INIT)
    //   - message size - checked above
    //   - cipher size - checked above
    //   - nonce size - checked above
    //   - shared_key size - checked above
    assert!(*SODIUM_INIT);
    unsafe {
        if libsodium_sys::crypto_secretbox_open_easy(
            raw_ptr_char!(message),
            raw_ptr_char_immut!(cipher),
            cipher.len() as libc::c_ulonglong,
            raw_ptr_char_immut!(nonce),
            raw_ptr_char_immut!(shared_key),
        ) == 0_i32
        {
            return Ok(());
        }
        Err(SodokenErrKind::InternalSodium.into())
    }
}
