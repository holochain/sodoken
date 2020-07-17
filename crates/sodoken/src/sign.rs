//! Api functions related to cryptographic signatures and verification.

use crate::*;

/// create an ed25519 signature keypair from a private seed
pub async fn sign_seed_keypair(
    pub_key: &mut Buffer,
    sec_key: &mut Buffer,
    seed: &Buffer,
) -> SodokenResult<()> {
    let pub_key = pub_key.clone();
    let sec_key = sec_key.clone();
    let seed = seed.clone();
    let (s, r) = tokio::sync::oneshot::channel();
    RAYON_POOL.spawn(move || {
        let mut pub_key = pub_key.write_lock();
        let mut sec_key = sec_key.write_lock();
        let seed = seed.read_lock();
        let r = safe::sodium::crypto_sign_seed_keypair(
            &mut pub_key,
            &mut sec_key,
            &seed,
        );
        let _ = s.send(r);
    });
    r.await.expect("threadpool task shutdown prematurely")
}

/// create an ed25519 signature keypair from entropy
pub async fn sign_keypair(
    pub_key: &mut Buffer,
    sec_key: &mut Buffer,
) -> SodokenResult<()> {
    let pub_key = pub_key.clone();
    let sec_key = sec_key.clone();
    let (s, r) = tokio::sync::oneshot::channel();
    RAYON_POOL.spawn(move || {
        let mut pub_key = pub_key.write_lock();
        let mut sec_key = sec_key.write_lock();
        let r = safe::sodium::crypto_sign_keypair(&mut pub_key, &mut sec_key);
        let _ = s.send(r);
    });
    r.await.expect("threadpool task shutdown prematurely")
}

/// create a signature from a signature private key
pub async fn sign_detached(
    signature: &mut Buffer,
    message: &Buffer,
    sec_key: &Buffer,
) -> SodokenResult<()> {
    let signature = signature.clone();
    let message = message.clone();
    let sec_key = sec_key.clone();
    let (s, r) = tokio::sync::oneshot::channel();
    RAYON_POOL.spawn(move || {
        let mut signature = signature.write_lock();
        let message = message.read_lock();
        let sec_key = sec_key.read_lock();
        let r = safe::sodium::crypto_sign_detached(
            &mut signature,
            &message,
            &sec_key,
        );
        let _ = s.send(r);
    });
    r.await.expect("threadpool task shutdown prematurely")
}

/// create a signature from a signature private key
pub async fn sign_verify_detached(
    signature: &Buffer,
    message: &Buffer,
    pub_key: &Buffer,
) -> SodokenResult<bool> {
    let signature = signature.clone();
    let message = message.clone();
    let pub_key = pub_key.clone();
    let (s, r) = tokio::sync::oneshot::channel();
    RAYON_POOL.spawn(move || {
        let signature = signature.read_lock();
        let message = message.read_lock();
        let pub_key = pub_key.read_lock();
        let r = safe::sodium::crypto_sign_verify_detached(
            &signature, &message, &pub_key,
        );
        let _ = s.send(r);
    });
    r.await.expect("threadpool task shutdown prematurely")
}
