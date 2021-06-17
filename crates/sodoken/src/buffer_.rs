use crate::*;
use parking_lot::{
    Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
use std::{
    borrow::{Borrow, BorrowMut},
    convert::{AsMut, AsRef},
    fmt::{Debug, Formatter},
    ops::{Deref, DerefMut},
    sync::Arc,
};

/// Indicates we can dereference an item as a readable byte array.
pub trait AsRead<'a>:
    'a + Deref<Target = [u8]> + AsRef<[u8]> + Borrow<[u8]>
{
}

/// Indicates we can dereference a sized item as a readable byte array.
pub trait AsReadSized<'a, const N: usize>:
    'a + Deref<Target = [u8; N]> + AsRef<[u8; N]> + Borrow<[u8; N]>
{
}

/// Indicates we can dereference an item as a mutable byte array.
pub trait AsWrite<'a>:
    'a + AsRead<'a> + DerefMut + AsMut<[u8]> + BorrowMut<[u8]>
{
}

/// Indicates we can dereference a sized item as a mutable byte array.
pub trait AsWriteSized<'a, const N: usize>:
    'a + AsReadSized<'a, N> + DerefMut + AsMut<[u8; N]> + BorrowMut<[u8; N]>
{
}

/// A readable buffer that may or may not be mem_locked.
pub trait AsBufRead: 'static + Debug + Send + Sync {
    /// The length of this buffer.
    fn len(&self) -> usize;

    /// Is this buffer empty?
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Obtain read access to the underlying buffer.
    fn read_lock(&self) -> ReadGuard<'_>;
}

impl<T: AsBufRead + ?Sized> AsBufRead for Box<T> {
    fn len(&self) -> usize {
        AsBufRead::len(&**self)
    }

    fn read_lock(&self) -> ReadGuard<'_> {
        AsBufRead::read_lock(&**self)
    }
}

impl<T: AsBufRead + ?Sized> AsBufRead for Arc<T> {
    fn len(&self) -> usize {
        AsBufRead::len(&**self)
    }

    fn read_lock(&self) -> ReadGuard<'_> {
        AsBufRead::read_lock(&**self)
    }
}

/// A sized readable buffer that may or may not be mem_locked.
pub trait AsBufReadSized<const N: usize>:
    'static + AsBufRead + Debug + Send + Sync
{
    /// Obtain read access to the underlying buffer.
    fn read_lock_sized(&self) -> ReadGuardSized<'_, N>;

    /// Convert to an unsized BufRead instance
    /// without cloning internal data
    /// and without changing memory locking strategy.
    fn to_read_unsized(&self) -> BufRead;
}

impl<T: AsBufReadSized<N>, const N: usize> AsBufReadSized<N> for Box<T> {
    fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
        AsBufReadSized::read_lock_sized(&**self)
    }

    fn to_read_unsized(&self) -> BufRead {
        AsBufReadSized::to_read_unsized(&**self)
    }
}

impl<T: AsBufReadSized<N>, const N: usize> AsBufReadSized<N> for Arc<T> {
    fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
        AsBufReadSized::read_lock_sized(&**self)
    }

    fn to_read_unsized(&self) -> BufRead {
        AsBufReadSized::to_read_unsized(&**self)
    }
}

/// A writable buffer that may or may not be mem_locked.
pub trait AsBufWrite: AsBufRead {
    /// Obtain write access to the underlying buffer.
    fn write_lock(&self) -> WriteGuard<'_>;

    /// Downgrade this to a read-only reference
    /// without cloning internal data
    /// and without changing memory locking strategy.
    fn read_only(&self) -> BufRead;
}

impl<T: AsBufWrite + ?Sized> AsBufWrite for Box<T> {
    fn write_lock(&self) -> WriteGuard<'_> {
        AsBufWrite::write_lock(&**self)
    }

    fn read_only(&self) -> BufRead {
        AsBufWrite::read_only(&**self)
    }
}

impl<T: AsBufWrite + ?Sized> AsBufWrite for Arc<T> {
    fn write_lock(&self) -> WriteGuard<'_> {
        AsBufWrite::write_lock(&**self)
    }

    fn read_only(&self) -> BufRead {
        AsBufWrite::read_only(&**self)
    }
}

/// A writable buffer that may or may not be mem_locked.
pub trait AsBufWriteSized<const N: usize>:
    AsBufReadSized<N> + AsBufWrite
{
    /// Obtain write access to the underlying buffer.
    fn write_lock_sized(&self) -> WriteGuardSized<'_, N>;

    /// Downgrade this to a read-only reference
    /// without cloning internal data
    /// and without changing memory locking strategy.
    fn read_only_sized(&self) -> BufReadSized<N>;

    /// Convert to an unsized BufWrite instance
    /// without cloning internal data
    /// and without changing memory locking strategy.
    fn to_write_unsized(&self) -> BufWrite;
}

impl<T: AsBufWriteSized<N>, const N: usize> AsBufWriteSized<N> for Box<T> {
    fn write_lock_sized(&self) -> WriteGuardSized<'_, N> {
        AsBufWriteSized::write_lock_sized(&**self)
    }

    fn read_only_sized(&self) -> BufReadSized<N> {
        AsBufWriteSized::read_only_sized(&**self)
    }

    fn to_write_unsized(&self) -> BufWrite {
        AsBufWriteSized::to_write_unsized(&**self)
    }
}

impl<T: AsBufWriteSized<N>, const N: usize> AsBufWriteSized<N> for Arc<T> {
    fn write_lock_sized(&self) -> WriteGuardSized<'_, N> {
        AsBufWriteSized::write_lock_sized(&**self)
    }

    fn read_only_sized(&self) -> BufReadSized<N> {
        AsBufWriteSized::read_only_sized(&**self)
    }

    fn to_write_unsized(&self) -> BufWrite {
        AsBufWriteSized::to_write_unsized(&**self)
    }
}

/// A concrete read-only buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufRead(Arc<dyn AsBufRead>);

impl From<Vec<u8>> for BufRead {
    fn from(b: Vec<u8>) -> Self {
        let b: BufReadNoLock = b.into_boxed_slice().into();
        Self(Arc::new(b))
    }
}

impl From<Box<[u8]>> for BufRead {
    fn from(b: Box<[u8]>) -> Self {
        let b: BufReadNoLock = b.into();
        Self(Arc::new(b))
    }
}

impl From<BufReadNoLock> for BufRead {
    fn from(b: BufReadNoLock) -> Self {
        Self(Arc::new(b))
    }
}

impl BufRead {
    /// Consruct a new BufRead that is NOT mem_locked.
    pub fn new_no_lock(content: &[u8]) -> Self {
        content.to_vec().into()
    }
}

impl AsBufRead for BufRead {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }
}

/// A concrete sized read-only buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufReadSized<const N: usize>(Arc<dyn AsBufReadSized<N>>);

impl<const N: usize> From<[u8; N]> for BufReadSized<N> {
    fn from(b: [u8; N]) -> Self {
        let b: BufReadNoLockSized<N> = Arc::new(b);
        Self(Arc::new(b))
    }
}

impl<const N: usize> BufReadSized<N> {
    /// Construct a new BufReadSized that is NOT mem_locked.
    pub fn new_no_lock(content: [u8; N]) -> BufReadSized<N> {
        content.into()
    }

    /// Convert to an unsized BufRead instance
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn to_read_unsized(&self) -> BufRead {
        self.0.to_read_unsized()
    }
}

impl<const N: usize> AsBufRead for BufReadSized<N> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }
}

impl<const N: usize> AsBufReadSized<N> for BufReadSized<N> {
    fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
        self.0.read_lock_sized()
    }

    fn to_read_unsized(&self) -> BufRead {
        BufRead(Arc::new(self.clone()))
    }
}

/// A concrete writable buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufWrite(Arc<dyn AsBufWrite>);

impl From<Vec<u8>> for BufWrite {
    fn from(b: Vec<u8>) -> Self {
        let b: BufWriteNoLock = Arc::new(RwLock::new(b.into_boxed_slice()));
        Self(Arc::new(b))
    }
}

impl From<Box<[u8]>> for BufWrite {
    fn from(b: Box<[u8]>) -> Self {
        let b: BufWriteNoLock = Arc::new(RwLock::new(b));
        Self(Arc::new(b))
    }
}

impl From<BufWriteNoLock> for BufWrite {
    fn from(b: BufWriteNoLock) -> Self {
        Self(Arc::new(b))
    }
}

impl BufWrite {
    /// Consruct a new BufWrite that is NOT mem_locked.
    pub fn new_no_lock(size: usize) -> Self {
        vec![0; size].into()
    }

    /// Construct a new BufWrite that IS mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    pub fn new_mem_locked(size: usize) -> SodokenResult<Self> {
        Ok(Self(Arc::new(BufWriteMemLocked::new(size)?)))
    }

    /// Downgrade this to a read-only reference
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn read_only(&self) -> BufRead {
        self.0.read_only()
    }
}

impl AsBufRead for BufWrite {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }
}

impl AsBufWrite for BufWrite {
    fn write_lock(&self) -> WriteGuard<'_> {
        self.0.write_lock()
    }

    fn read_only(&self) -> BufRead {
        self.0.read_only()
    }
}

/// A concrete sized writable buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufWriteSized<const N: usize>(Arc<dyn AsBufWriteSized<N>>);

impl<const N: usize> From<[u8; N]> for BufWriteSized<N> {
    fn from(b: [u8; N]) -> Self {
        let b: BufWriteNoLockSized<N> = Arc::new(RwLock::new(b));
        Self(Arc::new(b))
    }
}

impl<const N: usize> From<BufWriteNoLockSized<N>> for BufWriteSized<N> {
    fn from(b: BufWriteNoLockSized<N>) -> Self {
        Self(Arc::new(b))
    }
}

impl<const N: usize> BufWriteSized<N> {
    /// Consruct a new BufWrite that is NOT mem_locked.
    pub fn new_no_lock() -> Self {
        [0; N].into()
    }

    /// Construct a new BufWrite that IS mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    pub fn new_mem_locked() -> SodokenResult<Self> {
        Ok(Self(Arc::new(BufWriteMemLockedSized::new()?)))
    }

    /// Downgrade this to a read-only reference
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn read_only(&self) -> BufRead {
        self.0.read_only()
    }

    /// Downgrade this to a read-only reference
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn read_only_sized(&self) -> BufReadSized<N> {
        self.0.read_only_sized()
    }

    /// Convert to an unsized BufWrite instance
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn to_write_unsized(&self) -> BufWrite {
        self.0.to_write_unsized()
    }
}

impl<const N: usize> AsBufRead for BufWriteSized<N> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }
}

impl<const N: usize> AsBufReadSized<N> for BufWriteSized<N> {
    fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
        self.0.read_lock_sized()
    }

    fn to_read_unsized(&self) -> BufRead {
        self.0.to_read_unsized()
    }
}

impl<const N: usize> AsBufWrite for BufWriteSized<N> {
    fn write_lock(&self) -> WriteGuard<'_> {
        self.0.write_lock()
    }

    fn read_only(&self) -> BufRead {
        self.0.read_only()
    }
}

impl<const N: usize> AsBufWriteSized<N> for BufWriteSized<N> {
    fn write_lock_sized(&self) -> WriteGuardSized<'_, N> {
        self.0.write_lock_sized()
    }

    fn read_only_sized(&self) -> BufReadSized<N> {
        self.0.read_only_sized()
    }

    fn to_write_unsized(&self) -> BufWrite {
        self.0.to_write_unsized()
    }
}

/// Additional types related to working with buffers.
pub mod buffer {
    use super::*;

    /// This concrete read-only buffer type is NOT mem_locked.
    pub type BufReadNoLock = Arc<[u8]>;

    impl AsBufRead for BufReadNoLock {
        fn len(&self) -> usize {
            (**self).len()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(&'a [u8]);
            impl Deref for X<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl AsRef<[u8]> for X<'_> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl Borrow<[u8]> for X<'_> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            let x = Box::new(X(&*self));
            ReadGuard(x)
        }
    }

    /// This concrete sized read-only buffer type is NOT mem_locked.
    pub type BufReadNoLockSized<const N: usize> = Arc<[u8; N]>;

    impl<const N: usize> AsBufRead for BufReadNoLockSized<N> {
        fn len(&self) -> usize {
            (**self).len()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(&'a [u8]);
            impl Deref for X<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl AsRef<[u8]> for X<'_> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl Borrow<[u8]> for X<'_> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            let x = Box::new(X(&**self));
            ReadGuard(x)
        }
    }

    impl<const N: usize> AsBufReadSized<N> for BufReadNoLockSized<N> {
        fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
            struct X<'a, const N: usize>(&'a [u8; N]);
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8; N];
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<const N: usize> AsRef<[u8; N]> for X<'_, N> {
                fn as_ref(&self) -> &[u8; N] {
                    &self.0
                }
            }
            impl<const N: usize> Borrow<[u8; N]> for X<'_, N> {
                fn borrow(&self) -> &[u8; N] {
                    &self.0
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            let x = Box::new(X(&*self));
            ReadGuardSized(x)
        }

        fn to_read_unsized(&self) -> BufRead {
            BufRead(Arc::new(self.clone()))
        }
    }

    /// This concrete writable buffer type is NOT mem_locked.
    pub type BufWriteNoLock = Arc<RwLock<Box<[u8]>>>;

    impl AsBufRead for BufWriteNoLock {
        fn len(&self) -> usize {
            self.read().len()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(RwLockReadGuard<'a, Box<[u8]>>);
            impl Deref for X<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl AsRef<[u8]> for X<'_> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl Borrow<[u8]> for X<'_> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            let x = Box::new(X(self.read()));
            ReadGuard(x)
        }
    }

    impl AsBufWrite for BufWriteNoLock {
        fn write_lock(&self) -> WriteGuard<'_> {
            struct X<'a>(RwLockWriteGuard<'a, Box<[u8]>>);
            impl Deref for X<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl DerefMut for X<'_> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.0
                }
            }
            impl AsRef<[u8]> for X<'_> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl AsMut<[u8]> for X<'_> {
                fn as_mut(&mut self) -> &mut [u8] {
                    &mut self.0
                }
            }
            impl Borrow<[u8]> for X<'_> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl BorrowMut<[u8]> for X<'_> {
                fn borrow_mut(&mut self) -> &mut [u8] {
                    &mut self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            impl<'a> AsWrite<'a> for X<'a> {}
            let x = Box::new(X(self.write()));
            WriteGuard(x)
        }

        fn read_only(&self) -> BufRead {
            BufRead(Arc::new(self.clone()))
        }
    }

    /// This concrete sized writable buffer type is NOT mem_locked.
    pub type BufWriteNoLockSized<const N: usize> = Arc<RwLock<[u8; N]>>;

    impl<const N: usize> AsBufRead for BufWriteNoLockSized<N> {
        fn len(&self) -> usize {
            self.read().len()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a, const N: usize>(RwLockReadGuard<'a, [u8; N]>);
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    &*self.0
                }
            }
            impl<const N: usize> AsRef<[u8]> for X<'_, N> {
                fn as_ref(&self) -> &[u8] {
                    &*self.0
                }
            }
            impl<const N: usize> Borrow<[u8]> for X<'_, N> {
                fn borrow(&self) -> &[u8] {
                    &*self.0
                }
            }
            impl<'a, const N: usize> AsRead<'a> for X<'a, N> {}
            let x = Box::new(X(self.read()));
            ReadGuard(x)
        }
    }

    impl<const N: usize> AsBufReadSized<N> for BufWriteNoLockSized<N> {
        fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
            struct X<'a, const N: usize>(RwLockReadGuard<'a, [u8; N]>);
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8; N];
                fn deref(&self) -> &Self::Target {
                    &*self.0
                }
            }
            impl<const N: usize> AsRef<[u8; N]> for X<'_, N> {
                fn as_ref(&self) -> &[u8; N] {
                    &*self.0
                }
            }
            impl<const N: usize> Borrow<[u8; N]> for X<'_, N> {
                fn borrow(&self) -> &[u8; N] {
                    &*self.0
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            let x = Box::new(X(self.read()));
            ReadGuardSized(x)
        }

        fn to_read_unsized(&self) -> BufRead {
            BufRead(Arc::new(self.clone()))
        }
    }

    impl<const N: usize> AsBufWrite for BufWriteNoLockSized<N> {
        fn write_lock(&self) -> WriteGuard<'_> {
            struct X<'a, const N: usize>(RwLockWriteGuard<'a, [u8; N]>);
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    &*self.0
                }
            }
            impl<const N: usize> DerefMut for X<'_, N> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut *self.0
                }
            }
            impl<const N: usize> AsRef<[u8]> for X<'_, N> {
                fn as_ref(&self) -> &[u8] {
                    &*self.0
                }
            }
            impl<const N: usize> AsMut<[u8]> for X<'_, N> {
                fn as_mut(&mut self) -> &mut [u8] {
                    &mut *self.0
                }
            }
            impl<const N: usize> Borrow<[u8]> for X<'_, N> {
                fn borrow(&self) -> &[u8] {
                    &*self.0
                }
            }
            impl<const N: usize> BorrowMut<[u8]> for X<'_, N> {
                fn borrow_mut(&mut self) -> &mut [u8] {
                    &mut *self.0
                }
            }
            impl<'a, const N: usize> AsRead<'a> for X<'a, N> {}
            impl<'a, const N: usize> AsWrite<'a> for X<'a, N> {}
            let x = Box::new(X(self.write()));
            WriteGuard(x)
        }

        fn read_only(&self) -> BufRead {
            BufRead(Arc::new(self.clone()))
        }
    }

    impl<const N: usize> AsBufWriteSized<N> for BufWriteNoLockSized<N> {
        fn write_lock_sized(&self) -> WriteGuardSized<'_, N> {
            struct X<'a, const N: usize>(RwLockWriteGuard<'a, [u8; N]>);
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8; N];
                fn deref(&self) -> &Self::Target {
                    &*self.0
                }
            }
            impl<const N: usize> DerefMut for X<'_, N> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut *self.0
                }
            }
            impl<const N: usize> AsRef<[u8; N]> for X<'_, N> {
                fn as_ref(&self) -> &[u8; N] {
                    &*self.0
                }
            }
            impl<const N: usize> AsMut<[u8; N]> for X<'_, N> {
                fn as_mut(&mut self) -> &mut [u8; N] {
                    &mut *self.0
                }
            }
            impl<const N: usize> Borrow<[u8; N]> for X<'_, N> {
                fn borrow(&self) -> &[u8; N] {
                    &*self.0
                }
            }
            impl<const N: usize> BorrowMut<[u8; N]> for X<'_, N> {
                fn borrow_mut(&mut self) -> &mut [u8; N] {
                    &mut *self.0
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            impl<'a, const N: usize> AsWriteSized<'a, N> for X<'a, N> {}
            let x = Box::new(X(self.write()));
            WriteGuardSized(x)
        }

        fn read_only_sized(&self) -> BufReadSized<N> {
            BufReadSized(Arc::new(self.clone()))
        }

        fn to_write_unsized(&self) -> BufWrite {
            BufWrite(Arc::new(self.clone()))
        }
    }

    /// A read guard, indicating we have gained access to read buffer memory.
    pub struct ReadGuard<'a>(pub Box<dyn 'a + AsRead<'a>>);

    impl Deref for ReadGuard<'_> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }

    impl AsRef<[u8]> for ReadGuard<'_> {
        fn as_ref(&self) -> &[u8] {
            self.0.deref()
        }
    }

    impl Borrow<[u8]> for ReadGuard<'_> {
        fn borrow(&self) -> &[u8] {
            self.0.deref()
        }
    }

    impl<'a> AsRead<'a> for ReadGuard<'a> {}

    /// A read guard, indicating we have gained access to read sized buffer memory.
    pub struct ReadGuardSized<'a, const N: usize>(
        pub Box<dyn 'a + AsReadSized<'a, N>>,
    );

    impl<'a, const N: usize> Deref for ReadGuardSized<'a, N> {
        type Target = [u8; N];

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }

    impl<'a, const N: usize> AsRef<[u8; N]> for ReadGuardSized<'a, N> {
        fn as_ref(&self) -> &[u8; N] {
            self.0.deref()
        }
    }

    impl<'a, const N: usize> Borrow<[u8; N]> for ReadGuardSized<'a, N> {
        fn borrow(&self) -> &[u8; N] {
            self.0.deref()
        }
    }

    impl<'a, const N: usize> AsReadSized<'a, N> for ReadGuardSized<'a, N> {}

    /// A write guard, indicating we have gained access to write buffer memory.
    pub struct WriteGuard<'a>(pub Box<dyn 'a + AsWrite<'a>>);

    impl Deref for WriteGuard<'_> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }

    impl DerefMut for WriteGuard<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.0.deref_mut()
        }
    }

    impl AsRef<[u8]> for WriteGuard<'_> {
        fn as_ref(&self) -> &[u8] {
            self.0.deref()
        }
    }

    impl AsMut<[u8]> for WriteGuard<'_> {
        fn as_mut(&mut self) -> &mut [u8] {
            self.0.deref_mut()
        }
    }

    impl Borrow<[u8]> for WriteGuard<'_> {
        fn borrow(&self) -> &[u8] {
            self.0.deref()
        }
    }

    impl BorrowMut<[u8]> for WriteGuard<'_> {
        fn borrow_mut(&mut self) -> &mut [u8] {
            self.0.deref_mut()
        }
    }

    impl<'a> AsRead<'a> for WriteGuard<'a> {}
    impl<'a> AsWrite<'a> for WriteGuard<'a> {}

    /// A write guard, indicating we have gained access to write sized buffer memory.
    pub struct WriteGuardSized<'a, const N: usize>(
        pub Box<dyn 'a + AsWriteSized<'a, N>>,
    );

    impl<'a, const N: usize> Deref for WriteGuardSized<'a, N> {
        type Target = [u8; N];

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }

    impl<'a, const N: usize> DerefMut for WriteGuardSized<'a, N> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.0.deref_mut()
        }
    }

    impl<'a, const N: usize> AsRef<[u8; N]> for WriteGuardSized<'a, N> {
        fn as_ref(&self) -> &[u8; N] {
            self.0.deref()
        }
    }

    impl<'a, const N: usize> AsMut<[u8; N]> for WriteGuardSized<'a, N> {
        fn as_mut(&mut self) -> &mut [u8; N] {
            self.0.deref_mut()
        }
    }

    impl<'a, const N: usize> Borrow<[u8; N]> for WriteGuardSized<'a, N> {
        fn borrow(&self) -> &[u8; N] {
            self.0.deref()
        }
    }

    impl<'a, const N: usize> BorrowMut<[u8; N]> for WriteGuardSized<'a, N> {
        fn borrow_mut(&mut self) -> &mut [u8; N] {
            self.0.deref_mut()
        }
    }

    impl<'a, const N: usize> AsReadSized<'a, N> for WriteGuardSized<'a, N> {}
    impl<'a, const N: usize> AsWriteSized<'a, N> for WriteGuardSized<'a, N> {}

    /// This read-only buffer type is mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    #[derive(Clone)]
    pub struct BufReadMemLocked(Arc<Mutex<safe::s3buf::S3Buf>>);

    impl Debug for BufReadMemLocked {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BufReadMemLocked").finish()
        }
    }

    impl AsBufRead for BufReadMemLocked {
        fn len(&self) -> usize {
            self.0.lock().len()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl Drop for X<'_> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl Deref for X<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    self.0.as_slice()
                }
            }
            impl AsRef<[u8]> for X<'_> {
                fn as_ref(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl Borrow<[u8]> for X<'_> {
                fn borrow(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            let g = self.0.lock();
            g.set_readable();
            ReadGuard(Box::new(X(g)))
        }
    }

    /// This sized read-only buffer type is mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    #[derive(Clone)]
    pub struct BufReadMemLockedSized<const N: usize>(
        Arc<Mutex<safe::s3buf::S3Buf>>,
    );

    impl<const N: usize> Debug for BufReadMemLockedSized<N> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BufReadMemLocked").finish()
        }
    }

    impl<const N: usize> AsBufRead for BufReadMemLockedSized<N> {
        fn len(&self) -> usize {
            self.0.lock().len()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a, const N: usize>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl<const N: usize> Drop for X<'_, N> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    self.0.as_slice()
                }
            }
            impl<const N: usize> AsRef<[u8]> for X<'_, N> {
                fn as_ref(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl<const N: usize> Borrow<[u8]> for X<'_, N> {
                fn borrow(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl<'a, const N: usize> AsRead<'a> for X<'a, N> {}
            let g = self.0.lock();
            g.set_readable();
            let x: X<N> = X(g);
            ReadGuard(Box::new(x))
        }
    }

    impl<const N: usize> AsBufReadSized<N> for BufReadMemLockedSized<N> {
        fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
            struct X<'a, const N: usize>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl<const N: usize> Drop for X<'_, N> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8; N];
                fn deref(&self) -> &Self::Target {
                    self.0.as_sized()
                }
            }
            impl<const N: usize> AsRef<[u8; N]> for X<'_, N> {
                fn as_ref(&self) -> &[u8; N] {
                    self.0.as_sized()
                }
            }
            impl<const N: usize> Borrow<[u8; N]> for X<'_, N> {
                fn borrow(&self) -> &[u8; N] {
                    self.0.as_sized()
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            let g = self.0.lock();
            g.set_readable();
            ReadGuardSized(Box::new(X(g)))
        }

        fn to_read_unsized(&self) -> BufRead {
            BufRead(Arc::new(self.clone()))
        }
    }

    /// This writable buffer type is mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    #[derive(Clone)]
    pub struct BufWriteMemLocked(Arc<Mutex<safe::s3buf::S3Buf>>);

    impl BufWriteMemLocked {
        /// Construct a new writable, mem_locked buffer.
        /// Use this for passwords / private keys, etc, but NOT everything,
        /// locked memory is a finite resource.
        pub fn new(size: usize) -> SodokenResult<Self> {
            Ok(Self(Arc::new(Mutex::new(safe::s3buf::S3Buf::new(size)?))))
        }
    }

    impl Debug for BufWriteMemLocked {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BufWriteMemLocked").finish()
        }
    }

    impl AsBufRead for BufWriteMemLocked {
        fn len(&self) -> usize {
            self.0.lock().len()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl Drop for X<'_> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl Deref for X<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    self.0.as_slice()
                }
            }
            impl AsRef<[u8]> for X<'_> {
                fn as_ref(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl Borrow<[u8]> for X<'_> {
                fn borrow(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            let g = self.0.lock();
            g.set_readable();
            ReadGuard(Box::new(X(g)))
        }
    }

    impl AsBufWrite for BufWriteMemLocked {
        fn write_lock(&self) -> WriteGuard<'_> {
            struct X<'a>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl Drop for X<'_> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl Deref for X<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    self.0.as_slice()
                }
            }
            impl DerefMut for X<'_> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    self.0.as_slice_mut()
                }
            }
            impl AsRef<[u8]> for X<'_> {
                fn as_ref(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl AsMut<[u8]> for X<'_> {
                fn as_mut(&mut self) -> &mut [u8] {
                    self.0.as_slice_mut()
                }
            }
            impl Borrow<[u8]> for X<'_> {
                fn borrow(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl BorrowMut<[u8]> for X<'_> {
                fn borrow_mut(&mut self) -> &mut [u8] {
                    self.0.as_slice_mut()
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            impl<'a> AsWrite<'a> for X<'a> {}
            let g = self.0.lock();
            g.set_writable();
            WriteGuard(Box::new(X(g)))
        }

        fn read_only(&self) -> BufRead {
            BufRead(Arc::new(self.clone()))
        }
    }

    /// This writable buffer type is mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    #[derive(Clone)]
    pub struct BufWriteMemLockedSized<const N: usize>(
        Arc<Mutex<safe::s3buf::S3Buf>>,
    );

    impl<const N: usize> BufWriteMemLockedSized<N> {
        /// Construct a new writable, mem_locked buffer.
        /// Use this for passwords / private keys, etc, but NOT everything,
        /// locked memory is a finite resource.
        pub fn new() -> SodokenResult<Self> {
            Ok(Self(Arc::new(Mutex::new(safe::s3buf::S3Buf::new(N)?))))
        }
    }

    impl<const N: usize> Debug for BufWriteMemLockedSized<N> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BufWriteMemLocked").finish()
        }
    }

    impl<const N: usize> AsBufRead for BufWriteMemLockedSized<N> {
        fn len(&self) -> usize {
            self.0.lock().len()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a, const N: usize>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl<const N: usize> Drop for X<'_, N> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    self.0.as_slice()
                }
            }
            impl<const N: usize> AsRef<[u8]> for X<'_, N> {
                fn as_ref(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl<const N: usize> Borrow<[u8]> for X<'_, N> {
                fn borrow(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl<'a, const N: usize> AsRead<'a> for X<'a, N> {}
            let g = self.0.lock();
            g.set_readable();
            let x: X<N> = X(g);
            ReadGuard(Box::new(x))
        }
    }

    impl<const N: usize> AsBufReadSized<N> for BufWriteMemLockedSized<N> {
        fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
            struct X<'a, const N: usize>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl<const N: usize> Drop for X<'_, N> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8; N];
                fn deref(&self) -> &Self::Target {
                    self.0.as_sized()
                }
            }
            impl<const N: usize> AsRef<[u8; N]> for X<'_, N> {
                fn as_ref(&self) -> &[u8; N] {
                    self.0.as_sized()
                }
            }
            impl<const N: usize> Borrow<[u8; N]> for X<'_, N> {
                fn borrow(&self) -> &[u8; N] {
                    self.0.as_sized()
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            let g = self.0.lock();
            g.set_readable();
            ReadGuardSized(Box::new(X(g)))
        }

        fn to_read_unsized(&self) -> BufRead {
            BufRead(Arc::new(self.clone()))
        }
    }

    impl<const N: usize> AsBufWrite for BufWriteMemLockedSized<N> {
        fn write_lock(&self) -> WriteGuard<'_> {
            struct X<'a, const N: usize>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl<const N: usize> Drop for X<'_, N> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    self.0.as_slice()
                }
            }
            impl<const N: usize> DerefMut for X<'_, N> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    self.0.as_slice_mut()
                }
            }
            impl<const N: usize> AsRef<[u8]> for X<'_, N> {
                fn as_ref(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl<const N: usize> AsMut<[u8]> for X<'_, N> {
                fn as_mut(&mut self) -> &mut [u8] {
                    self.0.as_slice_mut()
                }
            }
            impl<const N: usize> Borrow<[u8]> for X<'_, N> {
                fn borrow(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }
            impl<const N: usize> BorrowMut<[u8]> for X<'_, N> {
                fn borrow_mut(&mut self) -> &mut [u8] {
                    self.0.as_slice_mut()
                }
            }
            impl<'a, const N: usize> AsRead<'a> for X<'a, N> {}
            impl<'a, const N: usize> AsWrite<'a> for X<'a, N> {}
            let g = self.0.lock();
            g.set_writable();
            let x: X<N> = X(g);
            WriteGuard(Box::new(x))
        }

        fn read_only(&self) -> BufRead {
            BufRead(Arc::new(self.clone()))
        }
    }

    impl<const N: usize> AsBufWriteSized<N> for BufWriteMemLockedSized<N> {
        fn write_lock_sized(&self) -> WriteGuardSized<'_, N> {
            struct X<'a, const N: usize>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl<const N: usize> Drop for X<'_, N> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl<const N: usize> Deref for X<'_, N> {
                type Target = [u8; N];
                fn deref(&self) -> &Self::Target {
                    self.0.as_sized()
                }
            }
            impl<const N: usize> DerefMut for X<'_, N> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    self.0.as_sized_mut()
                }
            }
            impl<const N: usize> AsRef<[u8; N]> for X<'_, N> {
                fn as_ref(&self) -> &[u8; N] {
                    self.0.as_sized()
                }
            }
            impl<const N: usize> AsMut<[u8; N]> for X<'_, N> {
                fn as_mut(&mut self) -> &mut [u8; N] {
                    self.0.as_sized_mut()
                }
            }
            impl<const N: usize> Borrow<[u8; N]> for X<'_, N> {
                fn borrow(&self) -> &[u8; N] {
                    self.0.as_sized()
                }
            }
            impl<const N: usize> BorrowMut<[u8; N]> for X<'_, N> {
                fn borrow_mut(&mut self) -> &mut [u8; N] {
                    self.0.as_sized_mut()
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            impl<'a, const N: usize> AsWriteSized<'a, N> for X<'a, N> {}
            let g = self.0.lock();
            g.set_writable();
            WriteGuardSized(Box::new(X(g)))
        }

        fn read_only_sized(&self) -> BufReadSized<N> {
            BufReadSized(Arc::new(self.clone()))
        }

        fn to_write_unsized(&self) -> BufWrite {
            BufWrite(Arc::new(self.clone()))
        }
    }
}
use buffer::*;
