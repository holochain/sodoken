//! Api functions related to cryptographic box encryption / decryption.

use crate::*;

/// length of box seed
pub const BOX_CURVE25519XCHACHAPOLY1305_SEEDBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SEEDBYTES as usize;

/// length of box public key
pub const BOX_CURVE25519XCHACHAPOLY1305_PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
        as usize;

/// length of box secret key
pub const BOX_CURVE25519XCHACHAPOLY1305_SECRETKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES
        as usize;

/// length of box mac
pub const BOX_CURVE25519XCHACHAPOLY1305_MACBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;

/// create a box curve25519xchacha20poly1305 keypair from a private seed
pub async fn box_curve25519xchacha20poly1305_seed_keypair<P, S, Seed>(
    pub_key: P,
    sec_key: S,
    seed: Seed,
) -> SodokenResult<()>
where
    P: AsBufWrite,
    S: AsBufWrite,
    Seed: AsBufRead,
{
    tokio_exec(move || {
        let mut pub_key = pub_key.write_lock();
        let mut sec_key = sec_key.write_lock();
        let seed = seed.read_lock();
        safe::sodium::crypto_box_curve25519xchacha20poly1305_seed_keypair(
            &mut pub_key,
            &mut sec_key,
            &seed,
        )
    })
    .await
}

/// create a box curve25519xchacha20poly1305 keypair from entropy
pub async fn box_curve25519xchacha20poly1305_keypair<P, S>(
    pub_key: P,
    sec_key: S,
) -> SodokenResult<()>
where
    P: AsBufWrite,
    S: AsBufWrite,
{
    tokio_exec(move || {
        let mut pub_key = pub_key.write_lock();
        let mut sec_key = sec_key.write_lock();
        safe::sodium::crypto_box_curve25519xchacha20poly1305_keypair(
            &mut pub_key,
            &mut sec_key,
        )
    })
    .await
}

/// encrypt data with box_curve25519xchacha20poly1305 (extra easy)
pub async fn box_curve25519xchacha20poly1305_extra_easy<M, P, S>(
    message: M,
    dest_pub_key: P,
    src_sec_key: S,
) -> SodokenResult<BufReadNoLock>
where
    M: AsBufRead,
    P: AsBufRead,
    S: AsBufRead,
{
    tokio_exec(move || {
        let message = message.read_lock();
        let dest_pub_key = dest_pub_key.read_lock();
        let src_sec_key = src_sec_key.read_lock();
        let cipher =
            safe::sodium::crypto_box_curve25519xchacha20poly1305_extra_easy(
                &message,
                &dest_pub_key,
                &src_sec_key,
            )?;
        Ok(cipher.into_boxed_slice().into())
    })
    .await
}

/*
#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn sign() -> SodokenResult<()> {
        let pub_ = BufWrite::new_no_lock(sign::SIGN_PUBLICKEYBYTES);
        let sec = BufWrite::new_no_lock(sign::SIGN_SECRETKEYBYTES);
        let sig = BufWrite::new_no_lock(sign::SIGN_BYTES);
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
        let seed = BufRead::new_no_lock(&[0xdb; sign::SIGN_SEEDBYTES]);
        let pub_ = BufWrite::new_no_lock(sign::SIGN_PUBLICKEYBYTES);
        let sec = BufWrite::new_no_lock(sign::SIGN_SECRETKEYBYTES);
        let sig = BufWrite::new_no_lock(sign::SIGN_BYTES);
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
*/
