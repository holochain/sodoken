//! Api functions related to cryptographically secure randomness / entropy.

use crate::*;

/// Fill a buffer with cryptographically secure randomness
pub async fn randombytes_buf(buf: &mut Buffer) -> SodokenResult<()> {
    let buf = buf.clone(); // cheap refcount clone
    let (s, r) = tokio::sync::oneshot::channel();
    RAYON_POOL.spawn(move || {
        let mut buf = buf.write_lock();
        let r = safe::sodium::randombytes_buf(&mut buf);
        let _ = s.send(r);
    });
    r.await.expect("threadpool task shutdown prematurely")
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[tokio::test(threaded_scheduler)]
    async fn randombytes_buf() -> SodokenResult<()> {
        let e = Buffer::new(32);
        let mut b = e.deep_clone().unwrap();
        assert_eq!(&vec![0; 32], &b.read_lock().to_vec());
        random::randombytes_buf(&mut b).await?;
        assert_ne!(&vec![0; 32], &b.read_lock().to_vec());
        assert_ne!(*e.read_lock(), *b.read_lock());
        Ok(())
    }
}
