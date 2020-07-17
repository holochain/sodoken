#![deny(missing_docs)]
//! lib SOdium + haDOKEN = SODOKEN!

use once_cell::sync::Lazy;
use std::{
    fmt::{Debug, Formatter},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

static SODIUM_INIT: Lazy<bool> = Lazy::new(|| {
    safe::sodium::sodium_init().expect("can init libsodium");
    true
});

static RAYON_POOL: Lazy<rayon::ThreadPool> = Lazy::new(|| {
    rayon::ThreadPoolBuilder::new()
        // give us some minimal ability to time-slice between
        // multiple paralel operations on low cpu-count systems
        .num_threads(8)
        .build()
        .expect("failed to build sodoken rayon thread pool")
});

/// Until async traits are supported, we need to erase the type of future
/// in "async" trait methods.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct BoxFuture<'lt, T>(pub Pin<Box<dyn 'lt + Future<Output = T> + Send>>);

impl<'lt, T> BoxFuture<'lt, T> {
    /// Erase the specific type of future by boxing it up.
    pub fn new<F: 'lt + Future<Output = T> + Send>(f: F) -> Self {
        Self(Box::pin(f))
    }
}

impl<'lt, T> Future for BoxFuture<'lt, T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

impl<'lt, T> Debug for BoxFuture<'lt, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxFuture { .. }").finish()
    }
}

mod error;
pub use error::*;

pub(crate) mod safe;

mod buffer;
pub use buffer::*;

pub mod hash;
pub mod random;
pub mod sign;

#[cfg(test)]
mod tests {
    #[tokio::test(threaded_scheduler)]
    async fn test_sanity() -> Result<(), ()> {
        println!("yo");
        Ok(())
    }
}
