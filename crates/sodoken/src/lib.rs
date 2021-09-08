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

pub mod hash;
pub mod kdf;
pub mod kx;
pub mod random;
pub mod sealed_box;
pub mod secretstream;
pub mod sign;

#[cfg(test)]
mod test;
