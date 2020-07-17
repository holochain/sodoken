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
