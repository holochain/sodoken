//! Modules related to secret stream encryption / decryption.
//!
//! #### Example
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! use sodoken::secretstream::xchacha20poly1305::*;
//!
//! // both sides have a secret key
//! let key = sodoken::BufWriteSized::new_mem_locked().unwrap();
//! sodoken::random::bytes_buf(key.clone()).await.unwrap();
//! let key = key.to_read_sized();
//!
//! // -- encryption side -- //
//!
//! // initialize the stream
//! let header = sodoken::BufWriteSized::new_no_lock();
//! let mut enc = SecretStreamEncrypt::new(
//!     key.clone(),
//!     header.clone(),
//! ).unwrap();
//! let header = header.to_read_sized();
//!
//! // .. push any number of messages here .. //
//!
//! // push a final message
//! let cipher = sodoken::BufExtend::new_no_lock(0);
//! enc.push_final(
//!     b"test-message".to_vec(),
//!     <Option<sodoken::BufRead>>::None,
//!     cipher.clone(),
//! ).await.unwrap();
//! let cipher = cipher.to_read();
//!
//! // -- decryption side -- //
//!
//! // initialize the stream
//! let mut dec = SecretStreamDecrypt::new(key, header).unwrap();
//!
//! // .. read any number of messages here .. //
//!
//! // read the final message
//! let msg = sodoken::BufExtend::new_no_lock(0);
//! let tag = dec.pull(
//!     cipher,
//!     <Option<sodoken::BufRead>>::None,
//!     msg.clone(),
//! ).await.unwrap();
//!
//! assert_eq!(SecretStreamTag::Final, tag);
//! assert_eq!(
//!     "test-message",
//!     String::from_utf8_lossy(&*msg.read_lock()),
//! );
//! # }
//! ```

pub mod xchacha20poly1305;
