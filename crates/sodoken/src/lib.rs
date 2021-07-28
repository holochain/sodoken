#![deny(warnings)]
#![deny(missing_docs)]
//! lib SOdium + haDOKEN = SODOKEN!
//!
//! libsodium wrapper providing tokio safe memory secure api access.

mod statics;
use statics::SODIUM_INIT;
pub(crate) use statics::*;

mod error;
pub use error::*;

pub(crate) mod safe;

mod buffer_;
pub use buffer_::*;

pub mod argon2id;
pub mod blake2b;
pub mod box_curve25519xchacha20poly1305;
pub mod random;
pub mod secretstream_xchacha20poly1305;
pub mod sign;
