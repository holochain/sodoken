//! Libsodium crypto_kx types and functions.

use crate::*;

/// minimum generichash/blake2b output hash size
pub const BYTES_MIN: usize =
    libsodium_sys::crypto_generichash_blake2b_BYTES_MIN as usize;

/// maximum generichash/blake2b output hash size
pub const BYTES_MAX: usize =
    libsodium_sys::crypto_generichash_blake2b_BYTES_MAX as usize;

/// minimum generichash/blake2b key size
pub const KEYBYTES_MIN: usize =
    libsodium_sys::crypto_generichash_blake2b_BYTES_MIN as usize;

/// maximum generichash/blake2b key size
pub const KEYBYTES_MAX: usize =
    libsodium_sys::crypto_generichash_blake2b_BYTES_MAX as usize;

/// A blake2b hash function. Internally uses [Blake2bHash] struct.
/// If you have all the data ready to go, use this helper function.
pub fn blake2b_hash(
    hash: &mut [u8],
    message: &[u8],
    key: Option<&[u8]>,
) -> Result<()> {
    let mut hasher = Blake2bHash::new(hash.len(), key)?;
    hasher.update(message)?;
    hasher.finish(hash)
}

/// A blake2b hash struct.
pub struct Blake2bHash {
    state: libsodium_sys::crypto_generichash_blake2b_state,
    outsize: usize,
}

impl Blake2bHash {
    /// Construct a new blake2b hasher instance.
    pub fn new(outsize: usize, key: Option<&[u8]>) -> Result<Self> {
        if outsize
            < libsodium_sys::crypto_generichash_blake2b_BYTES_MIN as usize
            || outsize
                > libsodium_sys::crypto_generichash_blake2b_BYTES_MAX as usize
        {
            return Err(Error::other("bad hash size"));
        }

        let (key_len, key) = match key {
            Some(key) => {
                if key.len()
                    < libsodium_sys::crypto_generichash_blake2b_KEYBYTES_MIN
                        as usize
                    || key.len()
                        > libsodium_sys::crypto_generichash_blake2b_KEYBYTES_MAX
                            as usize
                {
                    return Err(Error::other("bad key size"));
                }
                (key.len(), raw_ptr_char_immut!(key))
            }
            None => (0, std::ptr::null()),
        };

        let mut state = libsodium_sys::crypto_generichash_blake2b_state {
            opaque: [0; 384],
        };

        // INVARIANTS:
        //   - sodium_init() was called (enforced by sodium_init())
        crate::sodium_init();
        unsafe {
            if libsodium_sys::crypto_generichash_blake2b_init(
                &mut state, key, key_len, outsize,
            ) == 0_i32
            {
                Ok(Self { state, outsize })
            } else {
                Err(Error::other("internal"))
            }
        }
    }

    /// Update with additional data.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        // INVARIANTS:
        //   - sodium_init() was called (enforced by new)
        unsafe {
            if libsodium_sys::crypto_generichash_blake2b_update(
                &mut self.state,
                raw_ptr_char_immut!(data),
                data.len() as libc::c_ulonglong,
            ) == 0_i32
            {
                Ok(())
            } else {
                Err(Error::other("internal"))
            }
        }
    }

    /// Finalize the hashing.
    pub fn finish(mut self, hash: &mut [u8]) -> Result<()> {
        if hash.len() != self.outsize {
            return Err(Error::other("bad hash size"));
        }

        // INVARIANTS:
        //   - sodium_init() was called (enforced by new)
        unsafe {
            if libsodium_sys::crypto_generichash_blake2b_final(
                &mut self.state,
                raw_ptr_char!(hash),
                hash.len(),
            ) == 0_i32
            {
                Ok(())
            } else {
                Err(Error::other("internal"))
            }
        }
    }
}
