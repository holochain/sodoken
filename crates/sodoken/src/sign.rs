//! Api functions related to cryptographic signatures and verification.

use crate::*;

/// length of sign seed
pub const SIGN_SEEDBYTES: usize = libsodium_sys::crypto_sign_SEEDBYTES as usize;

/// length of sign public key
pub const SIGN_PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize;

/// length of sign secret key
pub const SIGN_SECRETKEYBYTES: usize =
    libsodium_sys::crypto_sign_SECRETKEYBYTES as usize;

/// length of sign signature
pub const SIGN_BYTES: usize = libsodium_sys::crypto_sign_BYTES as usize;

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

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(threaded_scheduler)]
    async fn sign() -> SodokenResult<()> {
        let mut pub_ = Buffer::new(sign::SIGN_PUBLICKEYBYTES);
        let mut sec = Buffer::new(sign::SIGN_SECRETKEYBYTES);
        let mut sig = Buffer::new(sign::SIGN_BYTES);
        let msg: Buffer = b"test message".to_vec().into();

        sign::sign_keypair(&mut pub_, &mut sec).await?;
        sign::sign_detached(&mut sig, &msg, &sec).await?;
        assert!(sign::sign_verify_detached(&sig, &msg, &pub_).await?);

        {
            let mut g = sig.write_lock();
            let g: &mut [u8] = &mut g;
            g[0] = (std::num::Wrapping(g[0]) + std::num::Wrapping(1)).0;
        }

        assert!(!sign::sign_verify_detached(&sig, &msg, &pub_).await?);

        Ok(())
    }

    #[tokio::test(threaded_scheduler)]
    async fn sign_seed() -> SodokenResult<()> {
        let seed: Buffer = vec![0xdb; sign::SIGN_SEEDBYTES].into();
        let mut pub_ = Buffer::new(sign::SIGN_PUBLICKEYBYTES);
        let mut sec = Buffer::new(sign::SIGN_SECRETKEYBYTES);
        let mut sig = Buffer::new(sign::SIGN_BYTES);
        let msg: Buffer = b"test message".to_vec().into();

        sign::sign_seed_keypair(&mut pub_, &mut sec, &seed).await?;
        assert_eq!(
            "[58, 28, 40, 195, 57, 146, 138, 152, 205, 130, 156, 8, 219, 48, 231, 103, 104, 100, 171, 188, 98, 19, 196, 30, 190, 195, 143, 136, 78, 73, 226, 59]",
            format!("{:?}", &*pub_.read_lock()),
        );
        sign::sign_detached(&mut sig, &msg, &sec).await?;
        assert_eq!(
            "[191, 44, 78, 57, 143, 164, 177, 39, 117, 147, 1, 26, 116, 228, 103, 73, 119, 177, 10, 232, 28, 247, 91, 156, 193, 13, 148, 168, 220, 138, 2, 130, 182, 178, 3, 230, 178, 201, 33, 92, 185, 186, 10, 28, 68, 60, 243, 143, 104, 37, 3, 17, 26, 52, 214, 240, 134, 30, 60, 199, 231, 64, 98, 6]",
            format!("{:?}", &*sig.read_lock()),
        );
        assert!(sign::sign_verify_detached(&sig, &msg, &pub_).await?);

        {
            let mut g = sig.write_lock();
            let g: &mut [u8] = &mut g;
            g[0] = (std::num::Wrapping(g[0]) + std::num::Wrapping(1)).0;
        }

        assert!(!sign::sign_verify_detached(&sig, &msg, &pub_).await?);

        Ok(())
    }
}
