//! Api functions related to cryptographically secure randomness / entropy.
//!
//! #### Example
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! let salt: sodoken::BufWriteSized<{ sodoken::hash::argon2id::SALTBYTES }> =
//!     sodoken::BufWriteSized::new_no_lock();
//! sodoken::random::bytes_buf(salt.clone()).await.unwrap();
//! let salt = salt.to_read_sized();
//! # }
//! ```

use crate::*;

/// Fill a buffer with cryptographically secure randomness
pub async fn bytes_buf<B>(buf: B) -> SodokenResult<()>
where
    B: Into<BufWrite> + 'static + Send,
{
    let buf = buf.into();

    // it doesn't take very long to fill a small buffer with random bytes,
    // below this count, we can run inside a task,
    // above this amount, we should run in a blocking task
    // to make sure we don't hang up tokio core threads
    //
    // -- Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
    // -- 4 physical cores / 8 logical cores
    //
    // -- executed directly:
    // random/10240            time:   [67.758 us 68.029 us 68.348 us]
    //                         thrpt:  [142.88 MiB/s 143.55 MiB/s 144.13 MiB/s]
    // -- executed via spawn_blocking:
    // random/10240            time:   [77.238 us 77.775 us 78.389 us]
    //                         thrpt:  [124.58 MiB/s 125.56 MiB/s 126.44 MiB/s]
    //
    // at ~10KiB the overhead of spawn_blocking (~5/6 us) starts to become
    // less significant, so switch over to that to avoid starving other core
    // tokio tasks.
    const BLOCKING_THRESHOLD: usize = 1024 * 10;

    let len = buf.len();
    let exec_random = move || {
        let mut buf = buf.write_lock();
        safe::sodium::randombytes_buf(&mut buf)
    };

    if len <= BLOCKING_THRESHOLD {
        return exec_random();
    }
    tokio_exec_blocking(exec_random).await
}

#[cfg(test)]
mod tests {
    use crate::*;
    //use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn randombytes_buf() -> SodokenResult<()> {
        let buf = BufWrite::new_no_lock(32);
        random::bytes_buf(buf.clone()).await?;
        let data = buf.read_lock().to_vec();
        assert_ne!(&vec![0; 32], &data);

        Ok(())
    }
}
