//! Modules related to cryptographic secretbox encryption / decryption.
//!
//! #### Example SecretBox Encryption / Decryption
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! use sodoken::secretbox::xsalsa20poly1305::*;
//!
//! // generate a shared secret
//! let s_key = sodoken::BufWriteSized::new_mem_locked().unwrap();
//! sodoken::random::bytes_buf(s_key.clone()).await.unwrap();
//! let s_key = s_key.to_read_sized();
//!
//! // sender encrypts a message
//! let msg = b"test-message".to_vec();
//! let nonce = sodoken::BufWriteSized::new_no_lock();
//! sodoken::random::bytes_buf(nonce.clone()).await.unwrap();
//! let nonce = nonce.to_read_sized();
//! let cipher = easy(
//!     nonce.clone(),
//!     msg,
//!     s_key.clone(),
//! ).await.unwrap();
//!
//! // receiver decrypts the message
//! let msg_len = open_easy_msg_len(cipher.len());
//! let msg = sodoken::BufWrite::new_no_lock(msg_len);
//! open_easy(
//!     nonce,
//!     msg.clone(),
//!     cipher,
//!     s_key,
//! ).await.unwrap();
//! let msg = msg.to_read();
//! assert_eq!(
//!     "test-message",
//!     String::from_utf8_lossy(&*msg.read_lock()),
//! );
//! # }
//! ```

pub mod xchacha20poly1305;
pub mod xsalsa20poly1305;
