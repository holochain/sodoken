//! Api functions related to the blake2b generichash algorithm.

use crate::*;

/// minimum generichash/blake2b output hash size
pub const BYTES_MIN: usize =
    libsodium_sys::crypto_generichash_BYTES_MIN as usize;

/// maximum generichash/blake2b output hash size
pub const BYTES_MAX: usize =
    libsodium_sys::crypto_generichash_BYTES_MAX as usize;

/// minimum generichash/blake2b key size
pub const KEYBYTES_MIN: usize =
    libsodium_sys::crypto_generichash_BYTES_MIN as usize;

/// maximum generichash/blake2b key size
pub const KEYBYTES_MAX: usize =
    libsodium_sys::crypto_generichash_BYTES_MAX as usize;

/// blake2b hashing scheme
async fn hash_inner<H, M, K>(
    hash: H,
    message: M,
    key: Option<K>,
) -> SodokenResult<()>
where
    H: AsBufWrite,
    M: AsBufRead,
    K: AsBufRead,
{
    tokio_exec(move || {
        let mut hash = hash.write_lock();
        let message = message.read_lock();
        match key {
            Some(key) => {
                let key = key.read_lock();
                safe::sodium::crypto_generichash(
                    &mut hash,
                    &message,
                    Some(&key),
                )
            }
            None => safe::sodium::crypto_generichash(&mut hash, &message, None),
        }
    })
    .await
}

/// blake2b hashing scheme
pub async fn hash_with_key<H, M, K>(
    hash: H,
    message: M,
    key: K,
) -> SodokenResult<()>
where
    H: AsBufWrite,
    M: AsBufRead,
    K: AsBufRead,
{
    hash_inner(hash, message, Some(key)).await
}

/// blake2b hashing scheme
pub async fn hash<H, M>(hash: H, message: M) -> SodokenResult<()>
where
    H: AsBufWrite,
    M: AsBufRead,
{
    hash_inner::<H, M, BufRead>(hash, message, None).await
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn blake2b() -> SodokenResult<()> {
        let msg = BufRead::new_no_lock(b"test message");
        let hash = BufWrite::new_no_lock(blake2b::BYTES_MIN);
        blake2b::hash(hash.clone(), msg.clone()).await?;
        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );

        // also check that a trait-object works
        let msg2 = msg.clone();
        let msg2: Box<dyn AsBufRead> = Box::new(msg2);
        blake2b::hash(hash.clone(), msg2).await?;
        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );

        // also check that arc trait-object works
        let msg3 = msg.clone();
        let msg3: Arc<dyn AsBufRead> = Arc::new(msg3);
        blake2b::hash(hash.clone(), msg3).await?;
        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );

        Ok(())
    }
}
