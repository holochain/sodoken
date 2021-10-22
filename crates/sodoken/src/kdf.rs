//! Api functions related to cryptographically secure key derivation.
//!
//! #### Example Key Derivation
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! let parent_key = [0; 32];
//! let sub_key = sodoken::BufWrite::new_no_lock(32);
//! sodoken::kdf::derive_from_key(
//!     sub_key.clone(),
//!     42,           // index
//!     *b"CtxBytes", // context
//!     parent_key,
//! ).unwrap();
//! assert_eq!(&[236, 60, 149, 214], &sub_key.read_lock()[..4]);
//! # }
//! ```

use crate::*;

/// Byte length of kdf "context" parameter.
pub const CONTEXTBYTES: usize = libsodium_sys::crypto_kdf_CONTEXTBYTES as usize;

/// Byte length of kdf "parent" key.
pub const KEYBYTES: usize = libsodium_sys::crypto_kdf_KEYBYTES as usize;

/// Derive a subkey from a parent key.
pub fn derive_from_key<S, P>(
    sub_key: S,
    subkey_id: u64,
    ctx: [u8; CONTEXTBYTES],
    parent_key: P,
) -> SodokenResult<()>
where
    S: Into<BufWrite> + 'static + Send,
    P: Into<BufReadSized<KEYBYTES>> + 'static + Send,
{
    let sub_key = sub_key.into();
    let parent_key = parent_key.into();

    let mut sub_key = sub_key.write_lock();
    let parent_key = parent_key.read_lock_sized();
    safe::sodium::crypto_kdf_derive_from_key(
        &mut sub_key,
        subkey_id,
        &ctx,
        &parent_key,
    )
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_kdf() -> SodokenResult<()> {
        let w = BufWrite::new_no_lock(32);

        kdf::derive_from_key(w.clone(), 784766, *b"testtest", [0; 32]).unwrap();
        assert_eq!(
            &*w.read_lock(),
            &[
                39, 175, 42, 233, 255, 157, 93, 27, 118, 92, 101, 128, 215,
                143, 121, 178, 226, 230, 199, 107, 237, 138, 236, 200, 45, 3,
                225, 142, 251, 29, 27, 62
            ]
        );

        kdf::derive_from_key(w.clone(), 42, *b"imzombie", [0xd2; 32]).unwrap();
        assert_eq!(
            &*w.read_lock(),
            &[
                116, 196, 152, 37, 253, 254, 162, 221, 100, 109, 104, 94, 28,
                89, 195, 20, 70, 81, 229, 102, 38, 156, 235, 253, 145, 74, 93,
                177, 253, 130, 216, 253
            ]
        );

        Ok(())
    }
}
