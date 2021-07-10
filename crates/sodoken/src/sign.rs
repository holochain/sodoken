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
pub async fn sign_seed_keypair<P, S, Seed>(
    pub_key: P,
    sec_key: S,
    seed: Seed,
) -> SodokenResult<()>
where
    P: Into<BufWriteSized<SIGN_PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufWriteSized<SIGN_SECRETKEYBYTES>> + 'static + Send,
    Seed: Into<BufReadSized<SIGN_SEEDBYTES>> + 'static + Send,
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
pub async fn sign_keypair<P, S>(pub_key: P, sec_key: S) -> SodokenResult<()>
where
    P: Into<BufWriteSized<SIGN_PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufWriteSized<SIGN_SECRETKEYBYTES>> + 'static + Send,
{
    let pub_key = pub_key.into();
    let sec_key = sec_key.into();

    let mut pub_key = pub_key.write_lock_sized();
    let mut sec_key = sec_key.write_lock_sized();
    safe::sodium::crypto_sign_keypair(&mut pub_key, &mut sec_key)
}

/// create a signature from a signature private key
pub async fn sign_detached<Sig, M, S>(
    signature: Sig,
    message: M,
    sec_key: S,
) -> SodokenResult<()>
where
    Sig: Into<BufWriteSized<SIGN_BYTES>> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    S: Into<BufReadSized<SIGN_SECRETKEYBYTES>> + 'static + Send,
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
    tokio_exec_blocking(exec_sign).await
}

/// create a signature from a signature private key
pub async fn sign_verify_detached<Sig, M, P>(
    signature: Sig,
    message: M,
    pub_key: P,
) -> SodokenResult<bool>
where
    Sig: Into<BufReadSized<SIGN_BYTES>> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    P: Into<BufReadSized<SIGN_PUBLICKEYBYTES>> + 'static + Send,
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
    tokio_exec_blocking(exec_verify).await
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn sign() -> SodokenResult<()> {
        let pub_: BufWriteSized<{ sign::SIGN_PUBLICKEYBYTES }> =
            BufWriteSized::new_no_lock();
        let sec: BufWriteSized<{ sign::SIGN_SECRETKEYBYTES }> =
            BufWriteSized::new_mem_locked().unwrap();
        let sig: BufWriteSized<{ sign::SIGN_BYTES }> =
            BufWriteSized::new_no_lock();
        let msg = BufRead::new_no_lock(b"test message");

        sign::sign_keypair(pub_.clone(), sec.clone()).await?;
        sign::sign_detached(sig.clone(), msg.clone(), sec).await?;
        assert!(
            sign::sign_verify_detached(sig.clone(), msg.clone(), pub_.clone())
                .await?
        );

        {
            let mut g = sig.write_lock();
            let g: &mut [u8] = &mut g;
            g[0] = (std::num::Wrapping(g[0]) + std::num::Wrapping(1)).0;
        }

        assert!(!sign::sign_verify_detached(sig, msg, pub_).await?);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_seed() -> SodokenResult<()> {
        let seed: BufReadSized<{ sign::SIGN_SEEDBYTES }> =
            BufReadSized::new_no_lock([0xdb; sign::SIGN_SEEDBYTES]);
        let pub_: BufWriteSized<{ sign::SIGN_PUBLICKEYBYTES }> =
            BufWriteSized::new_no_lock();
        let sec: BufWriteSized<{ sign::SIGN_SECRETKEYBYTES }> =
            BufWriteSized::new_mem_locked().unwrap();
        let sig: BufWriteSized<{ sign::SIGN_BYTES }> =
            BufWriteSized::new_no_lock();
        let msg = BufRead::new_no_lock(b"test message");

        sign::sign_seed_keypair(pub_.clone(), sec.clone(), seed).await?;
        assert_eq!(
            "[58, 28, 40, 195, 57, 146, 138, 152, 205, 130, 156, 8, 219, 48, 231, 103, 104, 100, 171, 188, 98, 19, 196, 30, 190, 195, 143, 136, 78, 73, 226, 59]",
            format!("{:?}", &*pub_.read_lock()),
        );
        sign::sign_detached(sig.clone(), msg.clone(), sec).await?;
        assert_eq!(
            "[191, 44, 78, 57, 143, 164, 177, 39, 117, 147, 1, 26, 116, 228, 103, 73, 119, 177, 10, 232, 28, 247, 91, 156, 193, 13, 148, 168, 220, 138, 2, 130, 182, 178, 3, 230, 178, 201, 33, 92, 185, 186, 10, 28, 68, 60, 243, 143, 104, 37, 3, 17, 26, 52, 214, 240, 134, 30, 60, 199, 231, 64, 98, 6]",
            format!("{:?}", &*sig.read_lock()),
        );
        assert!(
            sign::sign_verify_detached(sig.clone(), msg.clone(), pub_.clone())
                .await?
        );

        {
            let mut g = sig.write_lock();
            let g: &mut [u8] = &mut g;
            g[0] = (std::num::Wrapping(g[0]) + std::num::Wrapping(1)).0;
        }

        assert!(!sign::sign_verify_detached(sig, msg, pub_).await?);

        Ok(())
    }
}
