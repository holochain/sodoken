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
    H: Into<BufWrite> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    K: Into<BufRead> + 'static + Send,
{
    let hash = hash.into();
    let message = message.into();

    // it doesn't take very long to hash a small amount,
    // below this count, we can run inside a task,
    // above this amount, we should run in a blocking task
    // to make sure we don't hang up tokio core threads
    //
    // -- Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
    // -- 4 physical cores / 8 logical cores
    //
    // -- executed directly:
    // blake2b/51200           time:   [45.831 us 45.906 us 45.995 us]
    //                         thrpt:  [1.0367 GiB/s 1.0387 GiB/s 1.0404 GiB/s]
    // -- executed via spawn_blocking:
    // blake2b/51200           time:   [52.361 us 52.810 us 53.291 us]
    //                         thrpt:  [916.26 MiB/s 924.60 MiB/s 932.53 MiB/s]
    //
    // at ~50KiB the overhead of spawn_blocking (~5/6 us) starts to become
    // less significant, so switch over to that to avoid starving other core
    // tokio tasks.
    const BLOCKING_THRESHOLD: usize = 1024 * 50;

    let len = message.len();
    let exec_hash = move || {
        let mut hash = hash.write_lock();
        let message = message.read_lock();
        match key {
            Some(key) => {
                let key = key.into();
                let key = key.read_lock();
                safe::sodium::crypto_generichash(
                    &mut hash,
                    &message,
                    Some(&key),
                )
            }
            None => safe::sodium::crypto_generichash(&mut hash, &message, None),
        }
    };

    if len <= BLOCKING_THRESHOLD {
        return exec_hash();
    }
    tokio_exec_blocking(exec_hash).await
}

/// blake2b hashing scheme
pub async fn hash_with_key<H, M, K>(
    hash: H,
    message: M,
    key: K,
) -> SodokenResult<()>
where
    H: Into<BufWrite> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
    K: Into<BufRead> + 'static + Send,
{
    hash_inner(hash, message, Some(key)).await
}

/// blake2b hashing scheme
pub async fn hash<H, M>(hash: H, message: M) -> SodokenResult<()>
where
    H: Into<BufWrite> + 'static + Send,
    M: Into<BufRead> + 'static + Send,
{
    hash_inner::<H, M, BufRead>(hash, message, None).await
}

#[cfg(test)]
mod tests {
    use crate::*;
    //use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn blake2b() -> SodokenResult<()> {
        let msg = BufRead::new_no_lock(b"test message");
        let hash = BufWrite::new_no_lock(hash::blake2b::BYTES_MIN);
        hash::blake2b::hash(hash.clone(), msg.clone()).await?;
        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );

        Ok(())
    }
}
