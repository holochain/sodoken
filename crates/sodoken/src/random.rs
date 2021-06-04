//! Api functions related to cryptographically secure randomness / entropy.

use crate::*;

/// Fill a buffer with cryptographically secure randomness
pub async fn randombytes_buf<B: AsBufWrite>(buf: B) -> SodokenResult<()> {
    tokio_exec(move || {
        let mut buf = buf.write_lock();
        safe::sodium::randombytes_buf(&mut buf)
    })
    .await
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn randombytes_buf() -> SodokenResult<()> {
        let buf = BufWrite::new_no_lock(32);
        random::randombytes_buf(buf.clone()).await?;
        let data = buf.read_lock().to_vec();
        assert_ne!(&vec![0; 32], &data);

        // also check that a trait-object works
        // and that it still refers to the same memory
        let buf2 = buf.clone();
        let buf2: Arc<dyn AsBufWrite> = Arc::new(buf2);
        random::randombytes_buf(buf2.clone()).await?;
        assert_ne!(&vec![0; 32], &*buf2.read_lock());
        assert_ne!(&data, &*buf2.read_lock());
        assert_eq!(&*buf.read_lock(), &*buf2.read_lock());

        Ok(())
    }
}
