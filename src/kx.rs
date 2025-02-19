//! Api functions related to cryptographically secure key exchange.
//!
//! #### Example Key Derivation
//!
//! ```
//! // server has a key pair
//! let mut pk_srv = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
//! let mut sk_srv = sodoken::SizedLockedArray::new().unwrap();
//! sodoken::crypto_box::xsalsa_keypair(&mut pk_srv, &mut sk_srv.lock())
//!     .unwrap();
//!
//! // client has a keypair
//! let mut pk_cli = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
//! let mut sk_cli = sodoken::SizedLockedArray::new().unwrap();
//! sodoken::crypto_box::xsalsa_keypair(&mut pk_cli, &mut sk_cli.lock())
//!     .unwrap();
//!
//! // client can perform a key exchange with just the server pk
//! let mut cli_rx = sodoken::SizedLockedArray::new().unwrap();
//! let mut cli_tx = sodoken::SizedLockedArray::new().unwrap();
//! sodoken::kx::client_session_keys(
//!     &mut cli_rx.lock(),
//!     &mut cli_tx.lock(),
//!     &pk_cli,
//!     &sk_cli.lock(),
//!     &pk_srv,
//! )
//! .unwrap();
//!
//! // server can perform a key exchange with just the client pk
//! let mut srv_rx = sodoken::SizedLockedArray::new().unwrap();
//! let mut srv_tx = sodoken::SizedLockedArray::new().unwrap();
//! sodoken::kx::server_session_keys(
//!     &mut srv_rx.lock(),
//!     &mut srv_tx.lock(),
//!     &pk_srv,
//!     &sk_srv.lock(),
//!     &pk_cli,
//! )
//! .unwrap();
//!
//! // both sides have the same keys
//! assert_eq!(&*cli_rx.lock(), &*srv_tx.lock());
//! assert_eq!(&*cli_tx.lock(), &*srv_rx.lock());
//! ```

use crate::*;

/// Byte length of kx public key.
pub const PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_kx_PUBLICKEYBYTES as usize;

/// Byte length of kx secret key.
pub const SECRETKEYBYTES: usize =
    libsodium_sys::crypto_kx_SECRETKEYBYTES as usize;

/// Byte length of kx session key.
pub const SESSIONKEYBYTES: usize =
    libsodium_sys::crypto_kx_SESSIONKEYBYTES as usize;

/// Generate session keys from the client perspective.
pub fn client_session_keys(
    rx: &mut [u8; SESSIONKEYBYTES],
    tx: &mut [u8; SESSIONKEYBYTES],
    client_pk: &[u8; PUBLICKEYBYTES],
    client_sk: &[u8; SECRETKEYBYTES],
    server_pk: &[u8; PUBLICKEYBYTES],
) -> Result<()> {
    // crypto_kx_client_session_keys mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_kx_client_session_keys(
            raw_ptr_char!(rx),
            raw_ptr_char!(tx),
            raw_ptr_char_immut!(client_pk),
            raw_ptr_char_immut!(client_sk),
            raw_ptr_char_immut!(server_pk),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}

/// Generate session keys from the server perspective.
pub fn server_session_keys(
    rx: &mut [u8; SESSIONKEYBYTES],
    tx: &mut [u8; SESSIONKEYBYTES],
    server_pk: &[u8; PUBLICKEYBYTES],
    server_sk: &[u8; SECRETKEYBYTES],
    client_pk: &[u8; PUBLICKEYBYTES],
) -> Result<()> {
    // crypto_kx_client_session_keys mainly fails from sizes enforced above
    //
    // INVARIANTS:
    //   - sodium_init() was called (enforced by sodium_init())
    crate::sodium_init();
    unsafe {
        if libsodium_sys::crypto_kx_server_session_keys(
            raw_ptr_char!(rx),
            raw_ptr_char!(tx),
            raw_ptr_char_immut!(server_pk),
            raw_ptr_char_immut!(server_sk),
            raw_ptr_char_immut!(client_pk),
        ) == 0_i32
        {
            Ok(())
        } else {
            Err(Error::other("internal"))
        }
    }
}
