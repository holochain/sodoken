//! libsodium crypto_secretstream_xchacha20poly1305 types and functions.

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

/// Create the encryption side of a secret stream.
pub fn init_push(
    header: &mut [u8; HEADERBYTES],
    key: &[u8; KEYBYTES],
) -> Result<State> {
    let mut state = State::default();

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
        return Ok(state);
    }

    Err(std::io::ErrorKind::Other.into())
}
