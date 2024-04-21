//! Api functions related to cryptographic secretbox encryption / decryption
//! using the xsalsa20poly1305 algorithm.
//!
//! See secretbox module-level documentation for usage examples.

use crate::legacy::*;

/// length of secretbox key
pub const KEYBYTES: usize =
    libsodium_sys::crypto_secretbox_xsalsa20poly1305_KEYBYTES as usize;

/// length of secretbox nonce
pub const NONCEBYTES: usize =
    libsodium_sys::crypto_secretbox_xsalsa20poly1305_NONCEBYTES as usize;

/// length of secretbox mac
pub const MACBYTES: usize =
    libsodium_sys::crypto_secretbox_xsalsa20poly1305_MACBYTES as usize;

/// encrypt data with crytpo_secretbox_xsalsa20poly1305_easy
pub async fn easy<N, M, K>(
    nonce: N,
    message: M,
    shared_key: K,
) -> SodokenResult<BufRead>
where
    N: Into<BufReadSized<NONCEBYTES>> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    K: Into<BufReadSized<KEYBYTES>> + 'static + Send,
{
    let nonce = nonce.into();
    let message = message.into();
    let shared_key = shared_key.into();
    tokio_exec_blocking(move || {
        let nonce = nonce.read_lock_sized();
        let message = message.read_lock();
        let shared_key = shared_key.read_lock_sized();
        let cipher = safe::sodium::crypto_secretbox_xsalsa20poly1305_easy(
            &nonce,
            &message,
            &shared_key,
        )?;
        Ok(cipher.into())
    })
    .await?
}

/// decrypt data with crypto_secretbox_xsalsa20poly1305_open_easy
pub async fn open_easy<N, M, C, K>(
    nonce: N,
    message: M,
    cipher: C,
    shared_key: K,
) -> SodokenResult<()>
where
    N: Into<BufReadSized<NONCEBYTES>> + 'static + Send,
    M: Into<BufWrite> + 'static + Send,
    C: Into<BufRead> + 'static + Send,
    K: Into<BufReadSized<KEYBYTES>> + 'static + Send,
{
    let nonce = nonce.into();
    let message = message.into();
    let cipher = cipher.into();
    let shared_key = shared_key.into();
    tokio_exec_blocking(move || {
        let nonce = nonce.read_lock_sized();
        let mut message = message.write_lock();
        let cipher = cipher.read_lock();
        let shared_key = shared_key.read_lock_sized();
        safe::sodium::crypto_secretbox_xsalsa20poly1305_open_easy(
            &nonce,
            &mut message,
            &cipher,
            &shared_key,
        )
    })
    .await?
}

#[cfg(test)]
mod tests {
    use crate::legacy::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_secretbox() -> SodokenResult<()> {
        let nonce: BufReadSized<{ secretbox::xsalsa20poly1305::NONCEBYTES }> =
            BufReadSized::new_no_lock(
                [0; secretbox::xsalsa20poly1305::NONCEBYTES],
            );
        let shared_key: BufWriteSized<
            { secretbox::xsalsa20poly1305::KEYBYTES },
        > = BufWriteSized::new_mem_locked()?;
        let msg = BufRead::new_no_lock(b"test message");

        random::bytes_buf(shared_key.clone()).await?;

        let cipher = secretbox::xsalsa20poly1305::easy(
            nonce.clone(),
            msg.clone(),
            shared_key.clone(),
        )
        .await?;
        assert_ne!(&*msg.read_lock(), &*cipher.read_lock());

        let msg_len =
            cipher.read_lock().len() - secretbox::xsalsa20poly1305::MACBYTES;
        let msg2 = BufWrite::new_no_lock(msg_len);

        secretbox::xsalsa20poly1305::open_easy(
            nonce.clone(),
            msg2.clone(),
            cipher.clone(),
            shared_key.clone(),
        )
        .await?;

        assert_eq!(&*msg.read_lock(), &*msg2.read_lock());

        Ok(())
    }
}
