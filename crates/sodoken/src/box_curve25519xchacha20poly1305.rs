//! Api functions related to cryptographic box encryption / decryption.

use crate::*;

/// length of box seed
pub const BOX_SEEDBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SEEDBYTES as usize;

/// length of box public key
pub const BOX_PUBLICKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
        as usize;

/// length of box secret key
pub const BOX_SECRETKEYBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES
        as usize;

/// length of box mac
pub const BOX_MACBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;

/// length of box nonce
pub const BOX_NONCEBYTES: usize =
    libsodium_sys::crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;

/// create a box curve25519xchacha20poly1305 keypair from a private seed
pub async fn box_seed_keypair<P, S, Seed>(
    pub_key: P,
    sec_key: S,
    seed: Seed,
) -> SodokenResult<()>
where
    P: AsBufWriteSized<BOX_PUBLICKEYBYTES>,
    S: AsBufWriteSized<BOX_SECRETKEYBYTES>,
    Seed: AsBufReadSized<BOX_SEEDBYTES>,
{
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
pub async fn box_keypair<P, S>(pub_key: P, sec_key: S) -> SodokenResult<()>
where
    P: AsBufWriteSized<BOX_PUBLICKEYBYTES>,
    S: AsBufWriteSized<BOX_SECRETKEYBYTES>,
{
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
pub async fn box_easy<N, M, P, S>(
    nonce: N,
    message: M,
    dest_pub_key: P,
    src_sec_key: S,
) -> SodokenResult<BufRead>
where
    N: AsBufReadSized<BOX_NONCEBYTES>,
    M: AsBufRead,
    P: AsBufReadSized<BOX_PUBLICKEYBYTES>,
    S: AsBufReadSized<BOX_SECRETKEYBYTES>,
{
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

/// calculate the message len for an easy cipher len
pub fn box_open_easy_msg_len(cipher_len: usize) -> usize {
    cipher_len - BOX_MACBYTES
}

/// decrypt data with box_curve25519xchacha20poly1305_open_easy
pub async fn box_open_easy<N, M, C, P, S>(
    nonce: N,
    message: M,
    cipher: C,
    src_pub_key: P,
    dest_sec_key: S,
) -> SodokenResult<()>
where
    N: AsBufReadSized<BOX_NONCEBYTES>,
    M: AsBufWrite,
    C: AsBufRead,
    P: AsBufReadSized<BOX_PUBLICKEYBYTES>,
    S: AsBufReadSized<BOX_SECRETKEYBYTES>,
{
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

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_box() -> SodokenResult<()> {
        let nonce: BufReadSized<
            { box_curve25519xchacha20poly1305::BOX_NONCEBYTES },
        > = BufReadSized::new_no_lock(
            [0; box_curve25519xchacha20poly1305::BOX_NONCEBYTES],
        );
        let src_pub_: BufWriteSized<
            { box_curve25519xchacha20poly1305::BOX_PUBLICKEYBYTES },
        > = BufWriteSized::new_no_lock();
        let src_sec: BufWriteSized<
            { box_curve25519xchacha20poly1305::BOX_SECRETKEYBYTES },
        > = BufWriteSized::new_mem_locked().unwrap();
        let dest_pub_: BufWriteSized<
            { box_curve25519xchacha20poly1305::BOX_PUBLICKEYBYTES },
        > = BufWriteSized::new_no_lock();
        let dest_sec: BufWriteSized<
            { box_curve25519xchacha20poly1305::BOX_SECRETKEYBYTES },
        > = BufWriteSized::new_mem_locked().unwrap();
        let msg = BufRead::new_no_lock(b"test message");

        box_curve25519xchacha20poly1305::box_keypair(
            src_pub_.clone(),
            src_sec.clone(),
        )
        .await?;
        box_curve25519xchacha20poly1305::box_keypair(
            dest_pub_.clone(),
            dest_sec.clone(),
        )
        .await?;

        let cipher = box_curve25519xchacha20poly1305::box_easy(
            nonce.clone(),
            msg.clone(),
            dest_pub_.clone(),
            src_sec.clone(),
        )
        .await?;
        assert_ne!(&*msg.read_lock(), &*cipher.read_lock());

        let msg_len = box_curve25519xchacha20poly1305::box_open_easy_msg_len(
            cipher.read_lock().len(),
        );
        let msg2 = BufWrite::new_no_lock(msg_len);

        box_curve25519xchacha20poly1305::box_open_easy(
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
            { box_curve25519xchacha20poly1305::BOX_NONCEBYTES },
        > = BufReadSized::new_no_lock(
            [0; box_curve25519xchacha20poly1305::BOX_NONCEBYTES],
        );
        let src_seed: BufReadSized<
            { box_curve25519xchacha20poly1305::BOX_SEEDBYTES },
        > = BufReadSized::new_no_lock(
            [0xdb; box_curve25519xchacha20poly1305::BOX_SEEDBYTES],
        );
        let src_pub_: BufWriteSized<
            { box_curve25519xchacha20poly1305::BOX_PUBLICKEYBYTES },
        > = BufWriteSized::new_no_lock();
        let src_sec: BufWriteSized<
            { box_curve25519xchacha20poly1305::BOX_SECRETKEYBYTES },
        > = BufWriteSized::new_mem_locked().unwrap();
        let dest_seed: BufReadSized<
            { box_curve25519xchacha20poly1305::BOX_SEEDBYTES },
        > = BufReadSized::new_no_lock(
            [0xbd; box_curve25519xchacha20poly1305::BOX_SEEDBYTES],
        );
        let dest_pub_: BufWriteSized<
            { box_curve25519xchacha20poly1305::BOX_PUBLICKEYBYTES },
        > = BufWriteSized::new_no_lock();
        let dest_sec: BufWriteSized<
            { box_curve25519xchacha20poly1305::BOX_SECRETKEYBYTES },
        > = BufWriteSized::new_mem_locked().unwrap();
        let msg = BufRead::new_no_lock(b"test message");

        box_curve25519xchacha20poly1305::box_seed_keypair(
            src_pub_.clone(),
            src_sec.clone(),
            src_seed.clone(),
        )
        .await?;
        box_curve25519xchacha20poly1305::box_seed_keypair(
            dest_pub_.clone(),
            dest_sec.clone(),
            dest_seed.clone(),
        )
        .await?;

        let cipher = box_curve25519xchacha20poly1305::box_easy(
            nonce.clone(),
            msg.clone(),
            dest_pub_.clone(),
            src_sec.clone(),
        )
        .await?;
        assert_ne!(&*msg.read_lock(), &*cipher.read_lock());

        let msg_len = box_curve25519xchacha20poly1305::box_open_easy_msg_len(
            cipher.read_lock().len(),
        );
        let msg2 = BufWrite::new_no_lock(msg_len);

        box_curve25519xchacha20poly1305::box_open_easy(
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
