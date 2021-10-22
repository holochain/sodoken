//! Api functions related to the blake2b generichash algorithm.
//!
//! Blake2b is a fast generic hashing algorithm.
//!
//! #### Example if you have all the data ahead of time:
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! let hash = <sodoken::BufWriteSized<32>>::new_no_lock();
//! sodoken::hash::blake2b::hash(
//!     hash.clone(),
//!     b"test-data".to_vec(),
//! ).await.unwrap();
//! let hash = hash.to_read_sized();
//! assert_eq!(&[168, 70, 104, 97], &hash.read_lock()[..4]);
//! # }
//! ```
//!
//! #### Stream hashing example:
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! let mut hasher = <sodoken::hash::blake2b::Blake2bHash<32>>::new().unwrap();
//! hasher.update(b"test".to_vec()).await.unwrap();
//! hasher.update(b"-".to_vec()).await.unwrap();
//! hasher.update(b"data".to_vec()).await.unwrap();
//! let hash = sodoken::BufWriteSized::new_no_lock();
//! hasher.finish(hash.clone()).unwrap();
//! let hash = hash.to_read_sized();
//! assert_eq!(&[168, 70, 104, 97], &hash.read_lock()[..4]);
//! # }
//! ```

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

/// A streaming hash instance.
pub struct Blake2bHash<const N: usize>(
    Option<libsodium_sys::crypto_generichash_state>,
);

impl<const N: usize> Blake2bHash<N> {
    /// Construct a new blake2b streaming hash instance
    pub fn new() -> SodokenResult<Self> {
        if N < libsodium_sys::crypto_generichash_BYTES_MIN as usize
            || N > libsodium_sys::crypto_generichash_BYTES_MAX as usize
        {
            return Err(SodokenErrKind::BadHashSize.into());
        }

        Ok(Self(Some(safe::sodium::crypto_generichash_init(None, N)?)))
    }

    /// Construct a new blake2b streaming hash instance with key
    pub fn with_key<K>(key: K) -> SodokenResult<Self>
    where
        K: Into<BufRead> + 'static + Send,
    {
        let key = key.into();
        let key = key.read_lock();
        Ok(Self(Some(safe::sodium::crypto_generichash_init(
            Some(&key),
            N,
        )?)))
    }

    /// Update with additional data
    pub async fn update<D>(&mut self, data: D) -> SodokenResult<()>
    where
        D: Into<BufRead> + 'static + Send,
    {
        let data = data.into();

        // extract our state, so we can invoke a static blocking task
        // we always put it back, so it's safe to unwrap().
        let mut state = self.0.take().unwrap();

        // copied from above, do we need to test this specifically?
        const BLOCKING_THRESHOLD: usize = 1024 * 50;

        let len = data.len();
        let mut exec = move || {
            let data = data.read_lock();
            let res =
                safe::sodium::crypto_generichash_update(&mut state, &data);
            (state, res)
        };

        if len <= BLOCKING_THRESHOLD {
            let (state, res) = exec();
            self.0 = Some(state);
            return res;
        }
        let (state, res) = tokio_exec_blocking(exec).await;
        self.0 = Some(state);
        res
    }

    /// Finalize the hashing, filling in the results
    pub fn finish<R>(mut self, result: R) -> SodokenResult<()>
    where
        R: Into<BufWriteSized<N>> + Send,
    {
        // extract our state, so we can invoke a static blocking task
        // we always put it back, so it's safe to unwrap().
        let state = self.0.take().unwrap();

        let result = result.into();
        let mut result = result.write_lock();

        safe::sodium::crypto_generichash_final(state, &mut result)?;

        Ok(())
    }
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

    #[tokio::test(flavor = "multi_thread")]
    async fn blake2b_stream() -> SodokenResult<()> {
        let msg = BufRead::new_no_lock(b"test ");
        let msg2 = BufRead::new_no_lock(b"message");
        let hash = BufWriteSized::new_no_lock();

        let mut hasher =
            <hash::blake2b::Blake2bHash<{ hash::blake2b::BYTES_MIN }>>::new()?;
        hasher.update(msg).await?;
        hasher.update(msg2).await?;

        hasher.finish(hash.clone())?;

        assert_eq!(
            "[153, 12, 203, 148, 189, 196, 68, 143, 36, 38, 97, 11, 155, 176, 16, 230]",
            format!("{:?}", &*hash.read_lock()),
        );

        Ok(())
    }
}
