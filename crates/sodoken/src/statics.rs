//! internal static globals

use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub(crate) static SODIUM_INIT: Lazy<bool> = Lazy::new(|| {
    crate::safe::sodium::sodium_init().expect("can init libsodium");
    true
});

pub(crate) static THREAD_LIMIT: Lazy<Arc<Semaphore>> = Lazy::new(|| {
    // as we're looking to provide fairly consistant experience on
    // potentially high-throughput workload, we try to balance
    // between os support for time slicing on low cpu count systems
    // and less context switching overhead on high cpu-count systems
    //
    // fyi, at the time of writing this, the default tokio
    // max_blocking_threads is 512.
    const THREAD_MIN: usize = 4;
    const THREAD_MAX: usize = 8;
    let thread_count = std::cmp::min(
        THREAD_MIN, // don't go below this thread count
        std::cmp::max(
            THREAD_MAX,      // don't go above this thread count
            num_cpus::get(), // otherwise use the number of cpus
        ),
    );

    Arc::new(Semaphore::new(thread_count))
});

/// Executes `f` on the tokio blocking thread pool and awaits the result.
pub(crate) async fn tokio_exec_blocking<T, F>(f: F) -> T
where
    T: 'static + Send,
    F: 'static + Send + FnOnce() -> T,
{
    let _permit = THREAD_LIMIT.acquire().await.expect("semaphore cancelled");
    tokio::task::spawn_blocking(f)
        .await
        .expect("blocking task shutdown prematurely")
}
