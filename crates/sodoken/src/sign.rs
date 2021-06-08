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
    P: AsBufWriteSized<SIGN_PUBLICKEYBYTES>,
    S: AsBufWriteSized<SIGN_SECRETKEYBYTES>,
    Seed: AsBufReadSized<SIGN_SEEDBYTES>,
{
    tokio_exec(move || {
        let mut pub_key = pub_key.write_lock_sized();
        let mut sec_key = sec_key.write_lock_sized();
        let seed = seed.read_lock_sized();
        safe::sodium::crypto_sign_seed_keypair(
            &mut pub_key,
            &mut sec_key,
            &seed,
        )
    })
    .await
}

/// create an ed25519 signature keypair from entropy
pub async fn sign_keypair<P, S>(pub_key: P, sec_key: S) -> SodokenResult<()>
where
    P: AsBufWriteSized<SIGN_PUBLICKEYBYTES>,
    S: AsBufWriteSized<SIGN_SECRETKEYBYTES>,
{
    tokio_exec(move || {
        let mut pub_key = pub_key.write_lock_sized();
        let mut sec_key = sec_key.write_lock_sized();
        safe::sodium::crypto_sign_keypair(&mut pub_key, &mut sec_key)
    })
    .await
}

/// create a signature from a signature private key
pub async fn sign_detached<Sig, M, S>(
    signature: Sig,
    message: M,
    sec_key: S,
) -> SodokenResult<()>
where
    Sig: AsBufWriteSized<SIGN_BYTES>,
    M: AsBufRead,
    S: AsBufReadSized<SIGN_SECRETKEYBYTES>,
{
    tokio_exec(move || {
        let mut signature = signature.write_lock_sized();
        let message = message.read_lock();
        let sec_key = sec_key.read_lock_sized();
        safe::sodium::crypto_sign_detached(&mut signature, &message, &sec_key)
    })
    .await
}

/// create a signature from a signature private key
pub async fn sign_verify_detached<Sig, M, P>(
    signature: Sig,
    message: M,
    pub_key: P,
) -> SodokenResult<bool>
where
    Sig: AsBufReadSized<SIGN_BYTES>,
    M: AsBufRead,
    P: AsBufReadSized<SIGN_PUBLICKEYBYTES>,
{
    tokio_exec(move || {
        let signature = signature.read_lock_sized();
        let message = message.read_lock();
        let pub_key = pub_key.read_lock_sized();
        safe::sodium::crypto_sign_verify_detached(
            &signature, &message, &pub_key,
        )
    })
    .await
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
