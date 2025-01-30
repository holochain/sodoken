//! Modules related to secret stream encryption / decryption.
//!
//! #### Example
//!
//! ```
//! // both sides have a secret key
//! let mut key = sodoken::LockedArray::new().unwrap();
//! sodoken::random::randombytes_buf(&mut *key.lock()).unwrap();
//!
//! // -- encryption side -- //
//!
//! // initialize the stream
//! let mut enc = sodoken::secretstream::State::default();
//! let mut header = [0; sodoken::secretstream::HEADERBYTES];
//! sodoken::secretstream::init_push(&mut enc, &mut header, &key.lock())
//!     .unwrap();
//!
//! // .. push any number of messages here .. //
//!
//! // push a final message
//! let msg = b"test-message";
//! let mut cipher = vec![0; msg.len() + sodoken::secretstream::ABYTES];
//! sodoken::secretstream::push(
//!     &mut enc,
//!     &mut cipher,
//!     msg,
//!     Some(b"test-adata"),
//!     sodoken::secretstream::Tag::Final,
//! ).unwrap();
//!
//! // -- decryption side -- //
//!
//! // initialize the stream
//! let mut dec = sodoken::secretstream::State::default();
//! sodoken::secretstream::init_pull(&mut dec, &header, &key.lock()).unwrap();
//!
//! // .. read any number of messages here .. //
//!
//! // read the final message
//! let mut msg = vec![0; cipher.len() - sodoken::secretstream::ABYTES];
//! let tag = sodoken::secretstream::pull(
//!     &mut dec,
//!     &mut msg,
//!     &cipher,
//!     Some(b"test-adata"),
//! ).unwrap();
//!
//! assert_eq!(sodoken::secretstream::Tag::Final, tag);
//! assert_eq!(
//!     "test-message",
//!     String::from_utf8_lossy(&msg),
//! );
//! ```

use crate::*;

/// Length of secretstream key.
pub const KEYBYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;

/// Additional byte count required for cipher buffers above message length.
pub const ABYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

/// Length of secretstream header bytes.
pub const HEADERBYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;

/// Tags associated with SecretStream messages.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
pub enum Tag {
    /// "Message" SecretStreamTag
    Message =
        libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8,

    /// "Push" SecretStreamTag
    Push = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_PUSH as u8,

    /// "Rekey" SecretStreamTag
    Rekey =
        libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_REKEY as u8,

    /// "Final" SecretStreamTag
    Final =
        libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8,
}

/// Internal secret stream state.
pub struct State(libsodium_sys::crypto_secretstream_xchacha20poly1305_state);

impl Default for State {
    fn default() -> Self {
        Self(libsodium_sys::crypto_secretstream_xchacha20poly1305_state {
            k: Default::default(),
            nonce: Default::default(),
            _pad: Default::default(),
        })
    }
}

/// Create the encryption side of a secretstream.
pub fn init_push(
    state: &mut State,
    header: &mut [u8; HEADERBYTES],
    key: &[u8; KEYBYTES],
) -> Result<()> {
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - sizes enforced by type system
    crate::sodium_init();
    let res = unsafe {
        libsodium_sys::crypto_secretstream_xchacha20poly1305_init_push(
            &mut state.0,
            raw_ptr_char!(header),
            raw_ptr_char_immut!(key),
        )
    };

    if res == 0_i32 {
        Ok(())
    } else {
        Err(Error::other("internal"))
    }
}

/// Encrypt a secretstream message.
pub fn push(
    state: &mut State,
    cipher: &mut [u8],
    message: &[u8],
    adata: Option<&[u8]>,
    tag: Tag,
) -> Result<()> {
    let (adata_len, adata) = match adata {
        Some(adata) => {
            (adata.len() as libc::c_ulonglong, raw_ptr_char_immut!(adata))
        }
        None => (0, std::ptr::null()),
    };

    if cipher.len() != message.len() + ABYTES {
        return Err(Error::other("invalid cipher len"));
    }

    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - sizes enforced by type system
    crate::sodium_init();
    let res = unsafe {
        let message_len = message.len() as libc::c_ulonglong;
        libsodium_sys::crypto_secretstream_xchacha20poly1305_push(
            &mut state.0,
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
        Ok(())
    } else {
        Err(Error::other("internal"))
    }
}

/// Create the decryption side of a secretstream.
pub fn init_pull(
    state: &mut State,
    header: &[u8; HEADERBYTES],
    key: &[u8; KEYBYTES],
) -> Result<()> {
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - sizes enforced by type system
    crate::sodium_init();
    let res = unsafe {
        libsodium_sys::crypto_secretstream_xchacha20poly1305_init_pull(
            &mut state.0,
            raw_ptr_char_immut!(header),
            raw_ptr_char_immut!(key),
        )
    };

    if res == 0_i32 {
        Ok(())
    } else {
        Err(Error::other("internal"))
    }
}

/// Decrypt a secretstream message.
pub fn pull(
    state: &mut State,
    message: &mut [u8],
    cipher: &[u8],
    adata: Option<&[u8]>,
) -> Result<Tag> {
    if message.len() != cipher.len() - ABYTES {
        return Err(Error::other("invalid message len"));
    }

    let mut tag = 0;

    let (adata_len, adata) = match adata {
        Some(adata) => {
            (adata.len() as libc::c_ulonglong, raw_ptr_char_immut!(adata))
        }
        None => (0, std::ptr::null()),
    };

    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    //   - sizes enforced by type system + msg_len calc above
    crate::sodium_init();
    let res = unsafe {
        let cipher_len = cipher.len() as libc::c_ulonglong;
        libsodium_sys::crypto_secretstream_xchacha20poly1305_pull(
            &mut state.0,
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
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
                => Tag::Message,
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_PUSH
                => Tag::Push,
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_REKEY
                => Tag::Rekey,
            libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL
                => Tag::Final,
            _ => return Err(Error::other("recv invalid tag")),
        };

        Ok(tag)
    } else {
        Err(Error::other("internal"))
    }
}

/// Manual rekey. The opposite side of the stream must rekey at the exact same
/// spot for this to work.
pub fn rekey(state: &mut State) {
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    crate::sodium_init();
    unsafe {
        libsodium_sys::crypto_secretstream_xchacha20poly1305_rekey(
            &mut state.0,
        );
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    #[test]
    fn secretstream() {
        let mut p1 = [0; sign::PUBLICKEYBYTES];
        let mut s1 = LockedArray::new().unwrap();
        sign::keypair(&mut p1, &mut s1.lock()).unwrap();

        let mut xp1 = [0; kx::PUBLICKEYBYTES];
        let mut xs1 = LockedArray::new().unwrap();
        sign::pk_to_curve25519(&mut xp1, &p1).unwrap();
        sign::sk_to_curve25519(&mut xs1.lock(), &s1.lock()).unwrap();

        let mut p2 = [0; sign::PUBLICKEYBYTES];
        let mut s2 = LockedArray::new().unwrap();
        sign::keypair(&mut p2, &mut s2.lock()).unwrap();

        let mut xp2 = [0; kx::PUBLICKEYBYTES];
        let mut xs2 = LockedArray::new().unwrap();
        sign::pk_to_curve25519(&mut xp2, &p2).unwrap();
        sign::sk_to_curve25519(&mut xs2.lock(), &s2.lock()).unwrap();

        let mut srx = LockedArray::new().unwrap();
        let mut stx = LockedArray::new().unwrap();
        kx::server_session_keys(
            &mut srx.lock(),
            &mut stx.lock(),
            &xp1,
            &xs1.lock(),
            &xp2,
        )
        .unwrap();

        let mut crx = LockedArray::new().unwrap();
        let mut ctx = LockedArray::new().unwrap();
        kx::client_session_keys(
            &mut crx.lock(),
            &mut ctx.lock(),
            &xp2,
            &xs2.lock(),
            &xp1,
        )
        .unwrap();

        assert_eq!(*srx.lock(), *ctx.lock());
        assert_eq!(*stx.lock(), *crx.lock());

        let mut sstate = secretstream::State::default();
        let mut header = [0; secretstream::HEADERBYTES];
        secretstream::init_push(&mut sstate, &mut header, &mut stx.lock())
            .unwrap();

        let mut cstate = secretstream::State::default();
        secretstream::init_pull(&mut cstate, &header, &mut crx.lock()).unwrap();

        let message = b"hello";
        let mut cipher = vec![0; secretstream::ABYTES + message.len()];
        secretstream::push(
            &mut sstate,
            &mut cipher,
            message,
            None,
            secretstream::Tag::Message,
        )
        .unwrap();

        let mut rmsg = vec![0; cipher.len() - secretstream::ABYTES];
        let rtag =
            secretstream::pull(&mut cstate, &mut rmsg, &cipher, None).unwrap();
        assert_eq!(secretstream::Tag::Message, rtag);
        assert_eq!(&rmsg, b"hello");
    }
}
