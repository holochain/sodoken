#![deny(warnings)]
#![deny(missing_docs)]
//! lib SOdium + haDOKEN = SODOKEN!
//!
//! libsodium wrapper providing tokio safe memory secure api access.
//!
//! [![Project](https://img.shields.io/badge/project-holochain-blue.svg?style=flat-square)](http://holochain.org/)
//! [![Forum](https://img.shields.io/badge/chat-forum%2eholochain%2enet-blue.svg?style=flat-square)](https://forum.holochain.org)
//! [![Chat](https://img.shields.io/badge/chat-chat%2eholochain%2enet-blue.svg?style=flat-square)](https://chat.holochain.org)
//!
//! [![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
//!
//! This crate-level documentation mainly describes how to work with the
//! sodoken buffer types. Please see the individual module-level documentation
//! for usage examples and descriptions of individual crypto functions.
//!
//! #### Sodoken Buffers
//!
//! Sodoken buffers provide implementors with the ability to optionally
//! use secured memory (mlock + mprotect) to mitigate some secret exposure
//! channels like disk swapping. Buffers created with `new_mem_locked`
//! are secured, buffers created with `new_no_lock` are not.
//!
//! Please note that on most systems, locked memory is a finite resource,
//! so you should use it for private keys, but not everything.
//!
//! All buffers are shallow-cloned by default, so `buf.clone()` or any of the
//! `buf.to_*()` apis will give you a reference to the same buffer. You
//! can deep clone the buffers with the `buf.deep_clone_mem_locked()` or
//! `buf.deep_clone_no_lock()` apis.
//!
//! In general, the steps for working with sodoken apis are:
//! - create a writable buffer
//! - shallow clone that buffer into an api
//! - translate that buffer into a read-only version for future use
//!
//! #### Buffer Example
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! // create a writable buffer
//! let salt: sodoken::BufWriteSized<{ sodoken::hash::argon2id::SALTBYTES }> =
//!     sodoken::BufWriteSized::new_no_lock();
//!
//! // shallow clone that buffer into an api
//! sodoken::random::bytes_buf(salt.clone()).await.unwrap();
//!
//! // translate that buffer into a read-only version for future use
//! let salt = salt.to_read_sized();
//! # }
//! ```

mod statics;
use statics::SODIUM_INIT;
pub(crate) use statics::*;

mod error;
pub use error::*;

pub(crate) mod safe;

mod buffer_;
pub use buffer_::*;

pub mod crypto_box;
pub mod hash;
pub mod kdf;
pub mod kx;
pub mod random;
pub mod secretbox;
pub mod secretstream;
pub mod sign;

#[cfg(test)]
mod test;
