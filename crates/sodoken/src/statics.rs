//! internal static globals

use once_cell::sync::Lazy;

pub(crate) static SODIUM_INIT: Lazy<bool> = Lazy::new(|| {
    crate::safe::sodium::sodium_init().expect("can init libsodium");
    true
});

/// Executes `f` on the tokio blocking thread pool and awaits the result.
pub(crate) async fn tokio_exec<T, F>(f: F) -> T
where
    T: 'static + Send,
    F: 'static + Send + FnOnce() -> T,
{
    let (s, r) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let result = f();
        let _ = s.send(result);
    });
    r.await.expect("threadpool task shutdown prematurely")
}
