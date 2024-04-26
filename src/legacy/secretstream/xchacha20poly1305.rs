//! Api functions related to secret stream encryption / decryption using
//! the xchacha20poly1305 algorithm.
//!
//! See the secretstream module-level documentation for usage examples.

use crate::legacy::*;

/// Length of secretstream key.
pub const KEYBYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;

/// Additional byte count required for cipher buffers above message length.
pub const ABYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

/// Length of secretstream header bytes.
pub const HEADERBYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;

/// A structure to facilitate secretstream encryption.
pub struct SecretStreamEncrypt(
    Option<libsodium_sys::crypto_secretstream_xchacha20poly1305_state>,
);

/// Tags associated with SecretStream messages.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
pub enum SecretStreamTag {
    /// "Message" SecretStreamTag
    Message =
        libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8,

    /// "Push" SecretStreamTag
    Push = libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_PUSH as u8,

    /// "Rekey" SecretStreamTag
    Rekey =
        libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_REKEY as u8,

    /// "Final" SecretStreamTag
    Final =
        libsodium_sys::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8,
}

impl SecretStreamEncrypt {
    /// Construct a new SecretStreamEncrypt instance.
    /// Also returns the encryption header bytes.
    pub fn new<K, H>(key: K, header: H) -> SodokenResult<Self>
    where
        K: Into<BufReadSized<KEYBYTES>> + 'static + Send,
        H: Into<BufExtend> + 'static + Send,
    {
        let key = key.into();
        let mut header = header.into();

        let key = key.read_lock_sized();
        let state =
            safe::sodium::crypto_secretstream_xchacha20poly1305_init_push(
                &key,
                &mut header,
            )?;
        Ok(Self(Some(state)))
    }

    /// private push helper
    async fn priv_push(
        &mut self,
        message: BufRead,
        adata: Option<BufRead>,
        tag: SecretStreamTag,
        mut cipher: BufExtend,
    ) -> SodokenResult<()> {
        // extract our state, so we can invoke a static blocking task
        // we always put it back, so it's safe to unwrap().
        let mut state = self.0.take().unwrap();

        // TODO actually benchmark this... we just copied from `sign`
        const BLOCKING_THRESHOLD: usize = 1024 * 10;

        let len = message.len();
        let exec_push = move || {
            let message = message.read_lock();
            let res = match adata {
                Some(adata) => {
                    let adata = adata.read_lock();
                    safe::sodium::crypto_secretstream_xchacha20poly1305_push(
                        &mut state,
                        &message,
                        Some(&adata),
                        tag,
                        &mut cipher,
                    )
                }
                None => {
                    safe::sodium::crypto_secretstream_xchacha20poly1305_push(
                        &mut state,
                        &message,
                        None,
                        tag,
                        &mut cipher,
                    )
                }
            };
            (state, res)
        };

        if len <= BLOCKING_THRESHOLD {
            let (state, res) = exec_push();
            self.0 = Some(state);
            return res;
        }
        let (state, res) = tokio_exec_blocking(exec_push).await?;
        self.0 = Some(state);
        res
    }

    /// Encrypt a "Message" tagged message onto the output stream.
    pub async fn push_message<M, A, C>(
        &mut self,
        message: M,
        adata: Option<A>,
        cipher: C,
    ) -> SodokenResult<()>
    where
        M: Into<BufRead> + 'static + Send,
        A: Into<BufRead> + 'static + Send,
        C: Into<BufExtend> + 'static + Send,
    {
        let message = message.into();
        let adata = adata.map(|a| a.into());
        let cipher = cipher.into();
        self.priv_push(message, adata, SecretStreamTag::Message, cipher)
            .await
    }

    /// Encrypt a "Push" tagged message onto the output stream.
    pub async fn push_push<M, A, C>(
        &mut self,
        message: M,
        adata: Option<A>,
        cipher: C,
    ) -> SodokenResult<()>
    where
        M: Into<BufRead> + 'static + Send,
        A: Into<BufRead> + 'static + Send,
        C: Into<BufExtend> + 'static + Send,
    {
        let message = message.into();
        let adata = adata.map(|a| a.into());
        let cipher = cipher.into();
        self.priv_push(message, adata, SecretStreamTag::Push, cipher)
            .await
    }

    /// Encrypt a "Rekey" tagged message onto the output stream.
    pub async fn push_rekey<M, A, C>(
        &mut self,
        message: M,
        adata: Option<A>,
        cipher: C,
    ) -> SodokenResult<()>
    where
        M: Into<BufRead> + 'static + Send,
        A: Into<BufRead> + 'static + Send,
        C: Into<BufExtend> + 'static + Send,
    {
        let message = message.into();
        let adata = adata.map(|a| a.into());
        let cipher = cipher.into();
        self.priv_push(message, adata, SecretStreamTag::Rekey, cipher)
            .await
    }

    /// Encrypt a "Final" tagged message onto the output stream.
    pub async fn push_final<M, A, C>(
        &mut self,
        message: M,
        adata: Option<A>,
        cipher: C,
    ) -> SodokenResult<()>
    where
        M: Into<BufRead> + 'static + Send,
        A: Into<BufRead> + 'static + Send,
        C: Into<BufExtend> + 'static + Send,
    {
        let message = message.into();
        let adata = adata.map(|a| a.into());
        let cipher = cipher.into();
        self.priv_push(message, adata, SecretStreamTag::Final, cipher)
            .await
    }

    /// Trigger a rekey without a tag.
    /// The decryption side must manually rekey at the same point.
    pub fn rekey(&mut self) {
        safe::sodium::crypto_secretstream_xchacha20poly1305_rekey(
            self.0.as_mut().unwrap(),
        );
    }
}

/// A structure to facilitate secretstream decryption.
pub struct SecretStreamDecrypt(
    Option<libsodium_sys::crypto_secretstream_xchacha20poly1305_state>,
);

impl SecretStreamDecrypt {
    /// Construct a new SecretStreamEncrypt instance.
    /// Also returns the encryption header bytes.
    pub fn new<K, H>(key: K, header: H) -> SodokenResult<Self>
    where
        K: Into<BufReadSized<KEYBYTES>> + 'static + Send,
        H: Into<BufReadSized<HEADERBYTES>> + 'static + Send,
    {
        let key = key.into();
        let header = header.into();

        let key = key.read_lock_sized();
        let header = header.read_lock_sized();
        let state =
            safe::sodium::crypto_secretstream_xchacha20poly1305_init_pull(
                &header, &key,
            )?;
        Ok(Self(Some(state)))
    }

    /// Decrypt a secret stream message, returning the associated tag.
    pub async fn pull<C, A, M>(
        &mut self,
        cipher: C,
        adata: Option<A>,
        message: M,
    ) -> SodokenResult<SecretStreamTag>
    where
        C: Into<BufRead> + 'static + Send,
        A: Into<BufRead> + 'static + Send,
        M: Into<BufExtend> + 'static + Send,
    {
        let cipher = cipher.into();
        let adata = adata.map(|a| a.into());
        let mut message = message.into();

        // extract our state, so we can invoke a static blocking task
        // we always put it back, so it's safe to unwrap().
        let mut state = self.0.take().unwrap();

        // TODO actually benchmark this... we just copied from `sign`
        const BLOCKING_THRESHOLD: usize = 1024 * 10;

        let len = cipher.len();
        let exec_pull = move || {
            let cipher = cipher.read_lock();
            let res = match adata {
                Some(adata) => {
                    let adata = adata.read_lock();
                    safe::sodium::crypto_secretstream_xchacha20poly1305_pull(
                        &mut state,
                        &mut message,
                        &cipher,
                        Some(&adata),
                    )
                }
                None => {
                    safe::sodium::crypto_secretstream_xchacha20poly1305_pull(
                        &mut state,
                        &mut message,
                        &cipher,
                        None,
                    )
                }
            };
            (state, res)
        };

        if len <= BLOCKING_THRESHOLD {
            let (state, res) = exec_pull();
            self.0 = Some(state);
            return res;
        }
        let (state, res) = tokio_exec_blocking(exec_pull).await?;
        self.0 = Some(state);
        res
    }

    /// Trigger a rekey without a tag.
    /// This should only be done in the exact same spot the encryption
    /// side did a manual rekey.
    pub fn rekey(&mut self) {
        safe::sodium::crypto_secretstream_xchacha20poly1305_rekey(
            self.0.as_mut().unwrap(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::legacy::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_secretstream() -> SodokenResult<()> {
        use secretstream::xchacha20poly1305::*;

        let key = BufWriteSized::new_no_lock();
        let cipher = BufExtend::new_no_lock(0);

        let mut enc = SecretStreamEncrypt::new(key.clone(), cipher.clone())?;
        let header_len = cipher.len();
        assert_eq!(HEADERBYTES, header_len);

        enc.push_message(
            b"test-msg".to_vec(),
            <Option<BufRead>>::None,
            cipher.clone(),
        )
        .await?;
        let test_msg_len = cipher.len();
        assert_eq!(HEADERBYTES + 25, test_msg_len);

        // test rekeying after the first "Message".
        enc.rekey();

        enc.push_push(
            b"test-push".to_vec(),
            <Option<BufRead>>::None,
            cipher.clone(),
        )
        .await?;
        let test_push_len = cipher.len();
        assert_eq!(HEADERBYTES + 51, test_push_len);

        enc.push_rekey(
            b"test-rekey".to_vec(),
            <Option<BufRead>>::None,
            cipher.clone(),
        )
        .await?;
        let test_rekey_len = cipher.len();
        assert_eq!(HEADERBYTES + 78, test_rekey_len);

        enc.push_final(
            b"test-final".to_vec(),
            <Option<BufRead>>::None,
            cipher.clone(),
        )
        .await?;
        let test_final_len = cipher.len();
        assert_eq!(HEADERBYTES + 105, test_final_len);

        println!(
            "cipher len: {} {:?}",
            cipher.len(),
            String::from_utf8_lossy(&*cipher.read_lock())
        );

        let mut dec = SecretStreamDecrypt::new(
            key,
            BufReadSized::from(&cipher.read_lock()[0..header_len]),
        )?;
        let msg = BufExtend::new_no_lock(0);

        let tag = dec
            .pull(
                BufRead::from(&cipher.read_lock()[header_len..test_msg_len]),
                <Option<BufRead>>::None,
                msg.clone(),
            )
            .await?;
        assert_eq!(SecretStreamTag::Message, tag);

        // test rekeying after the first "Message".
        dec.rekey();

        let tag = dec
            .pull(
                BufRead::from(&cipher.read_lock()[test_msg_len..test_push_len]),
                <Option<BufRead>>::None,
                msg.clone(),
            )
            .await?;
        assert_eq!(SecretStreamTag::Push, tag);

        let tag = dec
            .pull(
                BufRead::from(
                    &cipher.read_lock()[test_push_len..test_rekey_len],
                ),
                <Option<BufRead>>::None,
                msg.clone(),
            )
            .await?;
        assert_eq!(SecretStreamTag::Rekey, tag);

        let tag = dec
            .pull(
                BufRead::from(
                    &cipher.read_lock()[test_rekey_len..test_final_len],
                ),
                <Option<BufRead>>::None,
                msg.clone(),
            )
            .await?;
        assert_eq!(SecretStreamTag::Final, tag);

        assert_eq!(
            "test-msgtest-pushtest-rekeytest-final",
            String::from_utf8_lossy(&*msg.read_lock())
        );

        Ok(())
    }
}
