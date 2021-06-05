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

/// calculate the message len for an extra easy cipher len
pub fn box_curve25519xchacha20poly1305_open_extra_easy_msg_len(
    cipher_len: usize,
) -> usize {
    cipher_len
        - libsodium_sys::crypto_box_curve25519xchacha20poly1305_NONCEBYTES
            as usize
        - libsodium_sys::crypto_box_curve25519xchacha20poly1305_MACBYTES
            as usize
}

/// decrypt data with box_curve25519xchacha20poly1305 (extra easy)
pub async fn box_curve25519xchacha20poly1305_open_extra_easy<M, C, P, S>(
    message: M,
    cipher: C,
    src_pub_key: P,
    dest_sec_key: S,
) -> SodokenResult<()>
where
    M: AsBufWrite,
    C: AsBufRead,
    P: AsBufRead,
    S: AsBufRead,
{
    tokio_exec(move || {
        let mut message = message.write_lock();
        let cipher = cipher.read_lock();
        let src_pub_key = src_pub_key.read_lock();
        let dest_sec_key = dest_sec_key.read_lock();
        safe::sodium::crypto_box_curve25519xchacha20poly1305_open_extra_easy(
            &mut message,
            &cipher,
            &src_pub_key,
            &dest_sec_key,
        )
    })
    .await
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_box() -> SodokenResult<()> {
        let src_pub_ = BufWrite::new_no_lock(box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_PUBLICKEYBYTES);
        let src_sec = BufWrite::new_no_lock(box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_SECRETKEYBYTES);
        let dest_pub_ = BufWrite::new_no_lock(box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_PUBLICKEYBYTES);
        let dest_sec = BufWrite::new_no_lock(box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_SECRETKEYBYTES);
        let msg = BufRead::new_no_lock(b"test message");

        box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_keypair(src_pub_.clone(), src_sec.clone()).await?;
        box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_keypair(dest_pub_.clone(), dest_sec.clone()).await?;

        let cipher = box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_extra_easy(msg.clone(), dest_pub_.clone(), src_sec.clone()).await?;
        assert_ne!(&*msg.read_lock(), &*cipher.read_lock());

        let msg_len = box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_open_extra_easy_msg_len(cipher.len());
        let msg2 = BufWrite::new_no_lock(msg_len);

        box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_open_extra_easy(msg2.clone(), cipher.clone(), src_pub_.clone(), dest_sec.clone()).await?;

        assert_eq!(&*msg.read_lock(), &*msg2.read_lock());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_box_seed() -> SodokenResult<()> {
        let src_seed = BufRead::new_no_lock(&[0xdb; box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_SEEDBYTES]);
        let src_pub_ = BufWrite::new_no_lock(box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_PUBLICKEYBYTES);
        let src_sec = BufWrite::new_no_lock(box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_SECRETKEYBYTES);
        let dest_seed = BufRead::new_no_lock(&[0xbd; box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_SEEDBYTES]);
        let dest_pub_ = BufWrite::new_no_lock(box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_PUBLICKEYBYTES);
        let dest_sec = BufWrite::new_no_lock(box_curve25519xchacha20poly1305::BOX_CURVE25519XCHACHAPOLY1305_SECRETKEYBYTES);
        let msg = BufRead::new_no_lock(b"test message");

        box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_seed_keypair(src_pub_.clone(), src_sec.clone(), src_seed.clone()).await?;
        box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_seed_keypair(dest_pub_.clone(), dest_sec.clone(), dest_seed.clone()).await?;

        let cipher = box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_extra_easy(msg.clone(), dest_pub_.clone(), src_sec.clone()).await?;
        assert_ne!(&*msg.read_lock(), &*cipher.read_lock());

        let msg_len = box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_open_extra_easy_msg_len(cipher.len());
        let msg2 = BufWrite::new_no_lock(msg_len);

        box_curve25519xchacha20poly1305::box_curve25519xchacha20poly1305_open_extra_easy(msg2.clone(), cipher.clone(), src_pub_.clone(), dest_sec.clone()).await?;

        assert_eq!(&*msg.read_lock(), &*msg2.read_lock());

        Ok(())
    }
}
