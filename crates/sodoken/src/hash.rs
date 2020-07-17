//! Api functions related to digests and hashing.

use crate::*;

/// blake2b hashing scheme
pub async fn generichash(
    hash: &mut Buffer,
    message: &Buffer,
    key: Option<&Buffer>,
) -> SodokenResult<()> {
    let hash = hash.clone();
    let message = message.clone();
    let key = key.cloned();
    let (s, r) = tokio::sync::oneshot::channel();
    RAYON_POOL.spawn(move || {
        let mut hash = hash.write_lock();
        let message = message.read_lock();
        let r = match key {
            Some(key) => {
                let key = key.read_lock();
                safe::sodium::crypto_generichash(
                    &mut hash,
                    &message,
                    Some(&key),
                )
            }
            None => safe::sodium::crypto_generichash(&mut hash, &message, None),
        };
        let _ = s.send(r);
    });
    r.await.expect("threadpool task shutdown prematurely")
}
