#![deny(missing_docs)]
//! sodoken

use std::{
    fmt::{Debug, Formatter},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

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

#[cfg(test)]
mod tests {
    #[tokio::test(threaded_scheduler)]
    async fn test_sanity() -> Result<(), ()> {
        println!("yo");
        Ok(())
    }
}
