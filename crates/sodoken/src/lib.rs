#![deny(warnings)]
#![deny(missing_docs)]
//! lib SOdium + haDOKEN = SODOKEN!
//!
//! libsodium wrapper providing tokio safe memory secure api access.

mod statics;
use statics::SODIUM_INIT;
pub use statics::*;

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
