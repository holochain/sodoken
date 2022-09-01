//! Api functions related to cryptographic box encryption / decryption using
//! the curve25519xchacha20poly1305 algorithm.
//!
//! See crypto_box module-level documentation for usage examples.

use crate::*;

/// length of box seed
pub const SEEDBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SEEDBYTES as usize;

/// length of box public key
pub const PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
        as usize;

/// length of box secret key
pub const SECRETKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES
        as usize;

/// length of box mac
pub const MACBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;

/// length of box nonce
pub const NONCEBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;

/// sealed box extra bytes
pub const SEALBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize;

/// create a box curve25519xchacha20poly1305 keypair from a private seed
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
    tokio_exec_blocking(move || {
        let mut pub_key = pub_key.write_lock_sized();
        let mut sec_key = sec_key.write_lock_sized();
        let seed = seed.read_lock_sized();
        safe::sodium::crypto_box_curve25519xchacha20poly1305_seed_keypair(
            &mut pub_key,
            &mut sec_key,
            &seed,
        )
    })
    .await
}

/// create a box curve25519xchacha20poly1305 keypair from entropy
pub async fn keypair<P, S>(pub_key: P, sec_key: S) -> SodokenResult<()>
where
    P: Into<BufWriteSized<PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufWriteSized<SECRETKEYBYTES>> + 'static + Send,
{
    let pub_key = pub_key.into();
    let sec_key = sec_key.into();
    tokio_exec_blocking(move || {
        let mut pub_key = pub_key.write_lock_sized();
        let mut sec_key = sec_key.write_lock_sized();
        safe::sodium::crypto_box_curve25519xchacha20poly1305_keypair(
            &mut pub_key,
            &mut sec_key,
        )
    })
    .await
}

/// encrypt data with box_curve25519xchacha20poly1305_easy
pub async fn easy<N, M, P, S>(
    nonce: N,
    message: M,
    dest_pub_key: P,
    src_sec_key: S,
) -> SodokenResult<BufRead>
where
    N: Into<BufReadSized<NONCEBYTES>> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    P: Into<BufReadSized<PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufReadSized<SECRETKEYBYTES>> + 'static + Send,
{
    let nonce = nonce.into();
    let message = message.into();
    let dest_pub_key = dest_pub_key.into();
    let src_sec_key = src_sec_key.into();
    tokio_exec_blocking(move || {
        let nonce = nonce.read_lock_sized();
        let message = message.read_lock();
        let dest_pub_key = dest_pub_key.read_lock_sized();
        let src_sec_key = src_sec_key.read_lock_sized();
        let cipher = safe::sodium::crypto_box_curve25519xchacha20poly1305_easy(
            &nonce,
            &message,
            &dest_pub_key,
            &src_sec_key,
        )?;
        Ok(cipher.into())
    })
    .await
}

/// decrypt data with box_curve25519xchacha20poly1305_open_easy
pub async fn open_easy<N, M, C, P, S>(
    nonce: N,
    message: M,
    cipher: C,
    src_pub_key: P,
    dest_sec_key: S,
) -> SodokenResult<()>
where
    N: Into<BufReadSized<NONCEBYTES>> + 'static + Send,
    M: Into<BufWrite> + 'static + Send,
    C: Into<BufRead> + 'static + Send,
    P: Into<BufReadSized<PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufReadSized<SECRETKEYBYTES>> + 'static + Send,
{
    let nonce = nonce.into();
    let message = message.into();
    let cipher = cipher.into();
    let src_pub_key = src_pub_key.into();
    let dest_sec_key = dest_sec_key.into();
    tokio_exec_blocking(move || {
        let nonce = nonce.read_lock_sized();
        let mut message = message.write_lock();
        let cipher = cipher.read_lock();
        let src_pub_key = src_pub_key.read_lock_sized();
        let dest_sec_key = dest_sec_key.read_lock_sized();
        safe::sodium::crypto_box_curve25519xchacha20poly1305_open_easy(
            &nonce,
            &mut message,
            &cipher,
            &src_pub_key,
            &dest_sec_key,
        )
    })
    .await
}

/// seal (encrypt) a message with an ephemeral key that can't even be decrypted
/// by this sender.
pub async fn seal<C, M, P>(
    cipher: C,
    message: M,
    dest_pub_key: P,
) -> SodokenResult<()>
where
    C: Into<BufWrite> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    P: Into<BufReadSized<PUBLICKEYBYTES>> + 'static + Send,
{
    let cipher = cipher.into();
    let message = message.into();
    let dest_pub_key = dest_pub_key.into();
    tokio_exec_blocking(move || {
        let mut cipher = cipher.write_lock();
        let message = message.read_lock();
        let dest_pub_key = dest_pub_key.read_lock_sized();
        safe::sodium::crypto_box_curve25519xchacha20poly1305_seal(
            &mut cipher,
            &message,
            &dest_pub_key,
        )
    })
    .await
}

/// open (decrypt) a sealed message.
pub async fn seal_open<M, C, P, S>(
    message: M,
    cipher: C,
    pub_key: P,
    sec_key: S,
) -> SodokenResult<()>
where
    M: Into<BufWrite> + 'static + Send,
    C: Into<BufRead> + 'static + Send,
    P: Into<BufReadSized<PUBLICKEYBYTES>> + 'static + Send,
    S: Into<BufReadSized<SECRETKEYBYTES>> + 'static + Send,
{
    let message = message.into();
    let cipher = cipher.into();
    let pub_key = pub_key.into();
    let sec_key = sec_key.into();
    tokio_exec_blocking(move || {
        let mut message = message.write_lock();
        let cipher = cipher.read_lock();
        let pub_key = pub_key.read_lock_sized();
        let sec_key = sec_key.read_lock_sized();
        safe::sodium::crypto_box_curve25519xchacha20poly1305_seal_open(
            &mut message,
            &cipher,
            &pub_key,
            &sec_key,
        )
    })
    .await
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_seal() -> SodokenResult<()> {
        use crypto_box::curve25519xchacha20poly1305::*;

        let dest_pub: BufWriteSized<{ PUBLICKEYBYTES }> =
            BufWriteSized::new_no_lock();
        let dest_sec: BufWriteSized<{ SECRETKEYBYTES }> =
            BufWriteSized::new_mem_locked().unwrap();

        keypair(dest_pub.clone(), dest_sec.clone()).await?;

        let message = BufRead::from(&b"hello"[..]);
        let cipher = BufWrite::new_no_lock(message.len() + SEALBYTES);

        seal(cipher.clone(), message, dest_pub.clone()).await?;

        let output = BufWrite::new_no_lock(cipher.len() - SEALBYTES);

        seal_open(output.clone(), cipher, dest_pub, dest_sec).await?;

        assert_eq!(b"hello", &*output.read_lock());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_box() -> SodokenResult<()> {
        let nonce: BufReadSized<
            { crypto_box::curve25519xchacha20poly1305::NONCEBYTES },
        > = BufReadSized::new_no_lock(
            [0; crypto_box::curve25519xchacha20poly1305::NONCEBYTES],
        );
        let src_pub_: BufWriteSized<
            { crypto_box::curve25519xchacha20poly1305::PUBLICKEYBYTES },
        > = BufWriteSized::new_no_lock();
        let src_sec: BufWriteSized<
            { crypto_box::curve25519xchacha20poly1305::SECRETKEYBYTES },
        > = BufWriteSized::new_mem_locked().unwrap();
        let dest_pub_: BufWriteSized<
            { crypto_box::curve25519xchacha20poly1305::PUBLICKEYBYTES },
        > = BufWriteSized::new_no_lock();
        let dest_sec: BufWriteSized<
            { crypto_box::curve25519xchacha20poly1305::SECRETKEYBYTES },
        > = BufWriteSized::new_mem_locked().unwrap();
        let msg = BufRead::new_no_lock(b"test message");

        crypto_box::curve25519xchacha20poly1305::keypair(
            src_pub_.clone(),
            src_sec.clone(),
        )
        .await?;
        crypto_box::curve25519xchacha20poly1305::keypair(
            dest_pub_.clone(),
            dest_sec.clone(),
        )
        .await?;

        let cipher = crypto_box::curve25519xchacha20poly1305::easy(
            nonce.clone(),
            msg.clone(),
            dest_pub_.clone(),
            src_sec.clone(),
        )
        .await?;
        assert_ne!(&*msg.read_lock(), &*cipher.read_lock());

        let msg_len = cipher.read_lock().len()
            - crypto_box::curve25519xchacha20poly1305::MACBYTES;
        let msg2 = BufWrite::new_no_lock(msg_len);

        crypto_box::curve25519xchacha20poly1305::open_easy(
            nonce.clone(),
            msg2.clone(),
            cipher.clone(),
            src_pub_.clone(),
            dest_sec.clone(),
        )
        .await?;

        assert_eq!(&*msg.read_lock(), &*msg2.read_lock());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_box_seed() -> SodokenResult<()> {
        let nonce: BufReadSized<
            { crypto_box::curve25519xchacha20poly1305::NONCEBYTES },
        > = BufReadSized::new_no_lock(
            [0; crypto_box::curve25519xchacha20poly1305::NONCEBYTES],
        );
        let src_seed: BufReadSized<
            { crypto_box::curve25519xchacha20poly1305::SEEDBYTES },
        > = BufReadSized::new_no_lock(
            [0xdb; crypto_box::curve25519xchacha20poly1305::SEEDBYTES],
        );
        let src_pub_: BufWriteSized<
            { crypto_box::curve25519xchacha20poly1305::PUBLICKEYBYTES },
        > = BufWriteSized::new_no_lock();
        let src_sec: BufWriteSized<
            { crypto_box::curve25519xchacha20poly1305::SECRETKEYBYTES },
        > = BufWriteSized::new_mem_locked().unwrap();
        let dest_seed: BufReadSized<
            { crypto_box::curve25519xchacha20poly1305::SEEDBYTES },
        > = BufReadSized::new_no_lock(
            [0xbd; crypto_box::curve25519xchacha20poly1305::SEEDBYTES],
        );
        let dest_pub_: BufWriteSized<
            { crypto_box::curve25519xchacha20poly1305::PUBLICKEYBYTES },
        > = BufWriteSized::new_no_lock();
        let dest_sec: BufWriteSized<
            { crypto_box::curve25519xchacha20poly1305::SECRETKEYBYTES },
        > = BufWriteSized::new_mem_locked().unwrap();
        let msg = BufRead::new_no_lock(b"test message");

        crypto_box::curve25519xchacha20poly1305::seed_keypair(
            src_pub_.clone(),
            src_sec.clone(),
            src_seed.clone(),
        )
        .await?;
        crypto_box::curve25519xchacha20poly1305::seed_keypair(
            dest_pub_.clone(),
            dest_sec.clone(),
            dest_seed.clone(),
        )
        .await?;

        let cipher = crypto_box::curve25519xchacha20poly1305::easy(
            nonce.clone(),
            msg.clone(),
            dest_pub_.clone(),
            src_sec.clone(),
        )
        .await?;
        assert_ne!(&*msg.read_lock(), &*cipher.read_lock());

        let msg_len = cipher.read_lock().len()
            - crypto_box::curve25519xchacha20poly1305::MACBYTES;
        let msg2 = BufWrite::new_no_lock(msg_len);

        crypto_box::curve25519xchacha20poly1305::open_easy(
            nonce.clone(),
            msg2.clone(),
            cipher.clone(),
            src_pub_.clone(),
            dest_sec.clone(),
        )
        .await?;

        assert_eq!(&*msg.read_lock(), &*msg2.read_lock());

        Ok(())
    }
}
