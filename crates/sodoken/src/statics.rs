//! internal static globals

use once_cell::sync::{Lazy, OnceCell};
use std::sync::Arc;

pub(crate) static SODIUM_INIT: Lazy<bool> = Lazy::new(|| {
    crate::safe::sodium::sodium_init().expect("can init libsodium");
    true
});

/// This is an Arc to make it easy to initialize things like sodoken.
static RAYON: OnceCell<Arc<rayon::ThreadPool>> = OnceCell::new();

/// Call this function before any other sodoken api if you wish to initialize
/// with a custom rayon pool. A default pool will be created if not.
/// Returns true if the sodoken rayon pool was previously uninitialized
/// and now holds the pool that was passed in to this function.
///
/// # Example
///
/// ```
/// # use sodoken::*;
/// # use std::sync::Arc;
/// init_once_rayon_thread_pool(|| Arc::new(rayon::ThreadPoolBuilder::new().build().unwrap()));
/// ```
pub fn init_once_rayon_thread_pool<F>(f: F) -> bool
where
    F: FnOnce() -> Arc<rayon::ThreadPool>,
{
    let mut did_init = false;
    let _ = RAYON.get_or_init(|| {
        did_init = true;
        f()
    });
    did_init
}

fn get_rayon() -> &'static Arc<rayon::ThreadPool> {
    RAYON.get_or_init(|| {
        // as we're looking to provide fairly consistant experience on
        // potentially high-throughput workload, we try to balance
        // between os support for time slicing on low cpu count systems
        // and less context switching overhead on high cpu-count systems
        // (with the assumption that tokio is also running threads)
        const THREAD_MIN: usize = 4;
        const THREAD_MAX: usize = 8;
        let thread_count = std::cmp::min(
            THREAD_MIN, // don't go below this thread count
            std::cmp::max(
                THREAD_MAX,      // don't go above this thread count
                num_cpus::get(), // otherwise use the number of cpus
            ),
        );

        Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build()
                .expect("failed to build rayon thread pool"),
        )
    })
}

/// Executes `f` on the rayon thread pool and awaits the result.
pub(crate) async fn rayon_exec<T, F>(f: F) -> T
where
    T: 'static + Send,
    F: 'static + Send + FnOnce() -> T,
{
    let (s, r) = tokio::sync::oneshot::channel();
    get_rayon().spawn(move || {
        let result = f();
        let _ = s.send(result);
    });
    r.await.expect("threadpool task shutdown prematurely")
}
