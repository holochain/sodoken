//! Libsodium random types and functions.

use crate::*;

/// Fill a buffer with cryptographically secure randomness.
pub fn randombytes_buf(buf: &mut [u8]) -> Result<()> {
    // randombytes_buf doesn't return anything and only acts on an already
    // allocated buffer - there are no error conditions possible here.
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    crate::sodium_init();
    unsafe {
        libsodium_sys::randombytes_buf(raw_ptr_void!(buf), buf.len());
        Ok(())
    }
}
