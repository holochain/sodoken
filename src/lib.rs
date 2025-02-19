#![deny(missing_docs)]
//! lib SOdium + haDOKEN = SODOKEN!
//!
//! Thin wrapper around libsodium-sys-stable.
//!
//! [![Project](https://img.shields.io/badge/project-holochain-blue.svg?style=flat-square)](http://holochain.org/)
//! [![Forum](https://img.shields.io/badge/chat-forum%2eholochain%2enet-blue.svg?style=flat-square)](https://forum.holochain.org)
//! [![Chat](https://img.shields.io/badge/chat-chat%2eholochain%2enet-blue.svg?style=flat-square)](https://chat.holochain.org)
//!
//! [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
//! [![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
//!
//! ```
//! use sodoken::*;
//!
//! let mut pub_key = [0; sign::PUBLICKEYBYTES];
//! let mut sec_key = SizedLockedArray::new().unwrap();
//!
//! sign::keypair(&mut pub_key, &mut sec_key.lock()).unwrap();
//!
//! let mut sig = [0; sign::SIGNATUREBYTES];
//!
//! sign::sign_detached(&mut sig, b"hello", &sec_key.lock()).unwrap();
//! assert!(sign::verify_detached(&sig, b"hello", &pub_key));
//! assert!(!sign::verify_detached(&sig, b"world", &pub_key));
//! ```

use std::io::{Error, Result};

pub(crate) fn sodium_init() {
    static I: std::sync::Once = std::sync::Once::new();
    I.call_once(|| unsafe {
        if libsodium_sys::sodium_init() < 0 {
            panic!("sodium_init allocation or threading error");
        }
    });
}

/// make invoking ffi functions more readable
#[allow(unused_macros)]
macro_rules! raw_ptr_void {
    ($name: ident) => {
        $name.as_mut_ptr() as *mut libc::c_void
    };
}

/// make invoking ffi functions more readable
macro_rules! raw_ptr_char {
    ($name: ident) => {
        $name.as_mut_ptr() as *mut libc::c_uchar
    };
}

/// make invoking ffi functions more readable
macro_rules! raw_ptr_char_immut {
    ($name: ident) => {
        $name.as_ptr() as *const libc::c_uchar
    };
}

/// make invoking ffi functions more readable
#[allow(unused_macros)]
macro_rules! raw_ptr_ichar_immut {
    ($name: ident) => {
        $name.as_ptr() as *const libc::c_char
    };
}

mod locked_mem;
pub use locked_mem::*;

pub mod argon2;
pub mod blake2b;
pub mod crypto_box;
pub mod kdf;
pub mod kx;
pub mod random;
pub mod secretbox;
pub mod secretstream;
pub mod sign;
