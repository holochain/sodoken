//! Modules related to cryptographic box encryption / decryption.
//!
//! #### Example Sealed Box Encryption / Decryption
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! use sodoken::crypto_box::curve25519xsalsa20poly1305::*;
//!
//! // recipient has a keypair
//! let pk = sodoken::BufWriteSized::new_no_lock();
//! let sk = sodoken::BufWriteSized::new_mem_locked().unwrap();
//! keypair(pk.clone(), sk.clone()).await.unwrap();
//! let pk = pk.to_read_sized();
//! let sk = sk.to_read_sized();
//!
//! // sender encrypts a message using receiver pub key
//! let msg = b"test-message".to_vec();
//! let cipher = sodoken::BufWrite::new_no_lock(msg.len() + SEALBYTES);
//! seal(cipher.clone(), msg, pk.clone()).await.unwrap();
//! let cipher = cipher.to_read();
//!
//! // recipient can decrypt the message
//! let msg = sodoken::BufWrite::new_no_lock(cipher.len() - SEALBYTES);
//! seal_open(msg.clone(), cipher, pk, sk).await.unwrap();
//! let msg = msg.to_read();
//! assert_eq!(
//!     "test-message",
//!     String::from_utf8_lossy(&*msg.read_lock()),
//! );
//! # }
//! ```
//!
//! #### Example Box Encryption / Decryption
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! use sodoken::crypto_box::curve25519xsalsa20poly1305::*;
//!
//! // recipient has a keypair
//! let r_pk = sodoken::BufWriteSized::new_no_lock();
//! let r_sk = sodoken::BufWriteSized::new_mem_locked().unwrap();
//! keypair(r_pk.clone(), r_sk.clone()).await.unwrap();
//! let r_pk = r_pk.to_read_sized();
//! let r_sk = r_sk.to_read_sized();
//!
//! // sender has a keypair
//! let s_pk = sodoken::BufWriteSized::new_no_lock();
//! let s_sk = sodoken::BufWriteSized::new_mem_locked().unwrap();
//! keypair(s_pk.clone(), s_sk.clone()).await.unwrap();
//! let s_pk = s_pk.to_read_sized();
//! let s_sk = s_sk.to_read_sized();
//!
//! // sender encrypts a message
//! let msg = b"test-message".to_vec();
//! let nonce = sodoken::BufWriteSized::new_no_lock();
//! sodoken::random::bytes_buf(nonce.clone()).await.unwrap();
//! let nonce = nonce.to_read_sized();
//! let cipher = easy(
//!     nonce.clone(),
//!     msg,
//!     r_pk.clone(),
//!     s_sk,
//! ).await.unwrap();
//!
//! // receiver decrypts the message
//! let msg_len = cipher.len() - MACBYTES;
//! let msg = sodoken::BufWrite::new_no_lock(msg_len);
//! open_easy(
//!     nonce,
//!     msg.clone(),
//!     cipher,
//!     s_pk,
//!     r_sk,
//! ).await.unwrap();
//! let msg = msg.to_read();
//! assert_eq!(
//!     "test-message",
//!     String::from_utf8_lossy(&*msg.read_lock()),
//! );
//! # }
//! ```

pub mod curve25519xchacha20poly1305;
pub mod curve25519xsalsa20poly1305;
