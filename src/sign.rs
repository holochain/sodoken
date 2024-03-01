//! Api functions related to cryptographic signatures and verification.
//!
//! #### Example
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! // we have a keypair
//! let pk: sodoken::BufWriteSized<{ sodoken::sign::PUBLICKEYBYTES }> =
//!     sodoken::BufWriteSized::new_no_lock();
//! let sk: sodoken::BufWriteSized<{ sodoken::sign::SECRETKEYBYTES }> =
//!     sodoken::BufWriteSized::new_mem_locked().unwrap();
//! sodoken::sign::keypair(pk.clone(), sk.clone()).await.unwrap();
//! let pk = pk.to_read_sized();
//! let sk = sk.to_read_sized();
//!
//! // we can generate a signature
//! let sig: sodoken::BufWriteSized<{ sodoken::sign::BYTES }> =
//!     sodoken::BufWriteSized::new_no_lock();
//! sodoken::sign::detached(
//!     sig.clone(),
//!     b"test message".to_vec(),
//!     sk,
//! ).await.unwrap();
//! let sig = sig.to_read_sized();
//!
//! // we can validate the signature
//! assert!(sodoken::sign::verify_detached(
//!     sig,
//!     b"test message".to_vec(),
//!     pk,
//! ).await.unwrap());
//! # }
//! ```

use crate::*;

/// length of sign seed
pub const SEEDBYTES: usize = libsodium_sys::crypto_sign_SEEDBYTES as usize;

/// length of sign public key
pub const PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_sign_PUBLICKEYBYTES as usize;

/// length of encryption public key
pub const X25519_PUBLICKEYBYTES: usize =
    crate::crypto_box::curve25519xsalsa20poly1305::PUBLICKEYBYTES;

/// length of encryption secret key
pub const X25519_SECRETKEYBYTES: usize =
    crate::crypto_box::curve25519xsalsa20poly1305::SECRETKEYBYTES;

/// length of sign secret key
pub const SECRETKEYBYTES: usize =
    libsodium_sys::crypto_sign_SECRETKEYBYTES as usize;

/// length of sign signature
pub const BYTES: usize = libsodium_sys::crypto_sign_BYTES as usize;

/// create an ed25519 signature keypair from a private seed
pub async fn seed_keypair<P, S, Seed>(
    pub_key: P,
    sec_key: S,
    seed: Seed,
) -> SodokenResult<()>
where
    P: Into<BufWriteSized<PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufWriteSized<SECRETKEYBYTES>> + 'static + Send,
    Seed: Into<BufReadSized<SEEDBYTES>> + 'static + Send,
{
    let pub_key = pub_key.into();
    let sec_key = sec_key.into();
    let seed = seed.into();

    let mut pub_key = pub_key.write_lock_sized();
    let mut sec_key = sec_key.write_lock_sized();
    let seed = seed.read_lock_sized();
    safe::sodium::crypto_sign_seed_keypair(&mut pub_key, &mut sec_key, &seed)
}

/// create an ed25519 signature keypair from entropy
pub async fn keypair<P, S>(pub_key: P, sec_key: S) -> SodokenResult<()>
where
    P: Into<BufWriteSized<PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufWriteSized<SECRETKEYBYTES>> + 'static + Send,
{
    let pub_key = pub_key.into();
    let sec_key = sec_key.into();

    let mut pub_key = pub_key.write_lock_sized();
    let mut sec_key = sec_key.write_lock_sized();
    safe::sodium::crypto_sign_keypair(&mut pub_key, &mut sec_key)
}

/// create a signature from a signature private key
pub async fn detached<Sig, M, S>(
    signature: Sig,
    message: M,
    sec_key: S,
) -> SodokenResult<()>
where
    Sig: Into<BufWriteSized<BYTES>> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    S: Into<BufReadSized<SECRETKEYBYTES>> + 'static + Send,
{
    let signature = signature.into();
    let message = message.into();
    let sec_key = sec_key.into();

    // it doesn't take very long to sign a small message,
    // below this count, we can run inside a task,
    // above this amount, we should run in a blocking task
    // to make sure we don't hang up tokio core threads
    //
    // -- Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
    // -- 4 physical cores / 8 logical cores
    //
    // -- executed directly:
    // sign_detached/10240     time:   [75.876 us 76.038 us 76.226 us]
    //                         thrpt:  [128.11 MiB/s 128.43 MiB/s 128.70 MiB/s]
    // -- executed via spawn_blocking:
    // sign_detached/10240     time:   [89.587 us 90.324 us 91.162 us]
    //                         thrpt:  [107.12 MiB/s 108.12 MiB/s 109.01 MiB/s]
    //
    // at ~10KiB the overhead of spawn_blocking (~5/6 us) starts to become
    // less significant, so switch over to that to avoid starving other core
    // tokio tasks.
    const BLOCKING_THRESHOLD: usize = 1024 * 10;

    let len = message.len();
    let exec_sign = move || {
        let mut signature = signature.write_lock_sized();
        let message = message.read_lock();
        let sec_key = sec_key.read_lock_sized();
        safe::sodium::crypto_sign_detached(&mut signature, &message, &sec_key)
    };

    if len <= BLOCKING_THRESHOLD {
        return exec_sign();
    }
    tokio_exec_blocking(exec_sign).await?
}

/// create a signature from a signature private key
pub async fn verify_detached<Sig, M, P>(
    signature: Sig,
    message: M,
    pub_key: P,
) -> SodokenResult<bool>
where
    Sig: Into<BufReadSized<BYTES>> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    P: Into<BufReadSized<PUBLICKEYBYTES>> + 'static + Send,
{
    let signature = signature.into();
    let message = message.into();
    let pub_key = pub_key.into();

    // it doesn't take very long to verify a small message,
    // below this count, we can run inside a task,
    // above this amount, we should run in a blocking task
    // to make sure we don't hang up tokio core threads
    //
    // -- Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
    // -- 4 physical cores / 8 logical cores
    //
    // -- executed directly:
    // sign_verify_detached/10240
    //                         time:   [91.999 us 92.228 us 92.479 us]
    //                         thrpt:  [105.60 MiB/s 105.89 MiB/s 106.15 MiB/s]
    // -- executed via spawn_blocking:
    // sign_verify_detached/10240
    //                         time:   [101.83 us 103.36 us 104.97 us]
    //                         thrpt:  [93.034 MiB/s 94.481 MiB/s 95.899 MiB/s]
    //
    // at ~10KiB the overhead of spawn_blocking (~5/6 us) starts to become
    // less significant, so switch over to that to avoid starving other core
    // tokio tasks.
    const BLOCKING_THRESHOLD: usize = 1024 * 10;

    let len = message.len();
    let exec_verify = move || {
        let signature = signature.read_lock_sized();
        let message = message.read_lock();
        let pub_key = pub_key.read_lock_sized();
        safe::sodium::crypto_sign_verify_detached(
            &signature, &message, &pub_key,
        )
    };

    if len <= BLOCKING_THRESHOLD {
        return exec_verify();
    }
    tokio_exec_blocking(exec_verify).await?
}

/// Convert a signing ed25519 public key into an encryption x25519 public key.
/// Please understand the downsides of this function before making use of it.
/// <https://doc.libsodium.org/advanced/ed25519-curve25519>
pub fn ed25519_pk_to_curve25519<E, S>(
    x25519_pk: E,
    ed25519_pk: S,
) -> SodokenResult<()>
where
    E: Into<BufWriteSized<X25519_PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufReadSized<PUBLICKEYBYTES>> + 'static + Send,
{
    let x25519_pk = x25519_pk.into();
    let ed25519_pk = ed25519_pk.into();

    let mut x25519_pk = x25519_pk.write_lock_sized();
    let ed25519_pk = ed25519_pk.read_lock_sized();
    safe::sodium::crypto_sign_ed25519_pk_to_curve25519(
        &mut x25519_pk,
        &ed25519_pk,
    )
}

/// Convert a signing ed25519 secret key into an encryption x25519 secret key.
/// Please understand the downsides of this function before making use of it.
/// <https://doc.libsodium.org/advanced/ed25519-curve25519>
pub fn ed25519_sk_to_curve25519<E, S>(
    x25519_sk: E,
    ed25519_sk: S,
) -> SodokenResult<()>
where
    E: Into<BufWriteSized<X25519_SECRETKEYBYTES>> + 'static + Send,
    S: Into<BufReadSized<SECRETKEYBYTES>> + 'static + Send,
{
    let x25519_sk = x25519_sk.into();
    let ed25519_sk = ed25519_sk.into();

    let mut x25519_sk = x25519_sk.write_lock_sized();
    let ed25519_sk = ed25519_sk.read_lock_sized();
    safe::sodium::crypto_sign_ed25519_sk_to_curve25519(
        &mut x25519_sk,
        &ed25519_sk,
    )
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn encrypt() {
        let epk: BufWriteSized<{ sign::PUBLICKEYBYTES }> =
            BufWriteSized::new_no_lock();
        let esk: BufWriteSized<{ sign::SECRETKEYBYTES }> =
            BufWriteSized::new_mem_locked().unwrap();
        let xpk: BufWriteSized<{ sign::X25519_PUBLICKEYBYTES }> =
            BufWriteSized::new_no_lock();
        let xsk: BufWriteSized<{ sign::X25519_SECRETKEYBYTES }> =
            BufWriteSized::new_mem_locked().unwrap();

        sign::keypair(epk.clone(), esk.clone()).await.unwrap();
        sign::ed25519_pk_to_curve25519(xpk.clone(), epk.clone()).unwrap();
        sign::ed25519_sk_to_curve25519(xsk.clone(), esk.clone()).unwrap();

        use crate::crypto_box::curve25519xsalsa20poly1305::*;

        let nonce: BufReadSized<NONCEBYTES> =
            BufReadSized::new_no_lock([0; NONCEBYTES]);
        let msg = BufRead::new_no_lock(b"test message");

        let cipher = easy(nonce.clone(), msg.clone(), xpk.clone(), xsk.clone())
            .await
            .unwrap();
        let msg_len = cipher.read_lock().len() - MACBYTES;
        let msg2 = BufWrite::new_no_lock(msg_len);
        open_easy(
            nonce.clone(),
            msg2.clone(),
            cipher.clone(),
            xpk.clone(),
            xsk.clone(),
        )
        .await
        .unwrap();

        assert_eq!(&*msg.read_lock(), &*msg2.read_lock());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign() -> SodokenResult<()> {
        let pub_: BufWriteSized<{ sign::PUBLICKEYBYTES }> =
            BufWriteSized::new_no_lock();
        let sec: BufWriteSized<{ sign::SECRETKEYBYTES }> =
            BufWriteSized::new_mem_locked().unwrap();
        let sig: BufWriteSized<{ sign::BYTES }> = BufWriteSized::new_no_lock();
        let msg = BufRead::new_no_lock(b"test message");

        sign::keypair(pub_.clone(), sec.clone()).await?;
        sign::detached(sig.clone(), msg.clone(), sec).await?;
        assert!(
            sign::verify_detached(sig.clone(), msg.clone(), pub_.clone())
                .await?
        );

        {
            let mut g = sig.write_lock();
            let g: &mut [u8] = &mut g;
            g[0] = (std::num::Wrapping(g[0]) + std::num::Wrapping(1)).0;
        }

        assert!(!sign::verify_detached(sig, msg, pub_).await?);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_seed() -> SodokenResult<()> {
        let seed: BufReadSized<{ sign::SEEDBYTES }> =
            BufReadSized::new_no_lock([0xdb; sign::SEEDBYTES]);
        let pub_: BufWriteSized<{ sign::PUBLICKEYBYTES }> =
            BufWriteSized::new_no_lock();
        let sec: BufWriteSized<{ sign::SECRETKEYBYTES }> =
            BufWriteSized::new_mem_locked().unwrap();
        let sig: BufWriteSized<{ sign::BYTES }> = BufWriteSized::new_no_lock();
        let msg = BufRead::new_no_lock(b"test message");

        sign::seed_keypair(pub_.clone(), sec.clone(), seed).await?;
        assert_eq!(
            "[58, 28, 40, 195, 57, 146, 138, 152, 205, 130, 156, 8, 219, 48, 231, 103, 104, 100, 171, 188, 98, 19, 196, 30, 190, 195, 143, 136, 78, 73, 226, 59]",
            format!("{:?}", &*pub_.read_lock()),
        );
        sign::detached(sig.clone(), msg.clone(), sec).await?;
        assert_eq!(
            "[191, 44, 78, 57, 143, 164, 177, 39, 117, 147, 1, 26, 116, 228, 103, 73, 119, 177, 10, 232, 28, 247, 91, 156, 193, 13, 148, 168, 220, 138, 2, 130, 182, 178, 3, 230, 178, 201, 33, 92, 185, 186, 10, 28, 68, 60, 243, 143, 104, 37, 3, 17, 26, 52, 214, 240, 134, 30, 60, 199, 231, 64, 98, 6]",
            format!("{:?}", &*sig.read_lock()),
        );
        assert!(
            sign::verify_detached(sig.clone(), msg.clone(), pub_.clone())
                .await?
        );

        {
            let mut g = sig.write_lock();
            let g: &mut [u8] = &mut g;
            g[0] = (std::num::Wrapping(g[0]) + std::num::Wrapping(1)).0;
        }

        assert!(!sign::verify_detached(sig, msg, pub_).await?);

        Ok(())
    }
}
