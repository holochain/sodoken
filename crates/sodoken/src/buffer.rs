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

/// Indicates we can dereference an item as a mutable byte array.
pub trait AsWrite<'a>:
    'a + AsRead<'a> + DerefMut + AsMut<[u8]> + BorrowMut<[u8]>
{
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

/// A readable buffer that may or may not be memlocked.
pub trait AsBufRead: 'static + Debug + Send + Sync {
    /// Obtain read access to the underlying buffer.
    fn read_lock(&self) -> ReadGuard<'_>;
}

impl<T: AsBufRead + ?Sized> AsBufRead for Box<T> {
    fn read_lock(&self) -> ReadGuard<'_> {
        AsBufRead::read_lock(&**self)
    }
}

impl<T: AsBufRead + ?Sized> AsBufRead for Arc<T> {
    fn read_lock(&self) -> ReadGuard<'_> {
        AsBufRead::read_lock(&**self)
    }
}

/// A writable buffer that may or may not be memlocked.
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

/// This concrete read-only buffer type is NOT memlocked.
pub type BufReadNoLock = Arc<[u8]>;

impl AsBufRead for BufReadNoLock {
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

/// Construct a new read-only buffer that is NOT memlocked.
pub fn new_buf_read_no_lock(content: &[u8]) -> BufReadNoLock {
    let buf: Box<[u8]> = content.to_vec().into_boxed_slice();
    buf.into()
}

/// This concrete writable buffer type is NOT memlocked.
pub type BufWriteNoLock = Arc<RwLock<Box<[u8]>>>;

/// Construct a new writable buffer that is NOT memlocked.
pub fn new_buf_write_no_lock(size: usize) -> BufWriteNoLock {
    let buf: Box<[u8]> = vec![0; size].into_boxed_slice();
    Arc::new(RwLock::new(buf))
}

impl AsBufRead for BufWriteNoLock {
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
        BufRead(BufReadInner::NoLockDowngrade(self.clone()))
    }
}

/// This read-only buffer type is memlocked.
/// Use this for passwords / private keys, etc, but NOT everything,
/// locked memory is a finite resource.
#[derive(Clone)]
pub struct BufReadMemlocked(Arc<Mutex<safe::s3buf::S3Buf>>);

impl Debug for BufReadMemlocked {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufReadMemlocked").finish()
    }
}

impl AsBufRead for BufReadMemlocked {
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
        let g = self.0.lock();
        g.set_readable();
        ReadGuard(Box::new(X(g)))
    }
}

/// This writable buffer type is memlocked.
/// Use this for passwords / private keys, etc, but NOT everything,
/// locked memory is a finite resource.
#[derive(Clone)]
pub struct BufWriteMemlocked(Arc<Mutex<safe::s3buf::S3Buf>>);

impl BufWriteMemlocked {
    /// Construct a new writable, memlocked buffer.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    pub fn new(size: usize) -> SodokenResult<Self> {
        Ok(Self(Arc::new(Mutex::new(safe::s3buf::S3Buf::new(size)?))))
    }

    /// Get a read-only, memlocked reference to this buffer.
    pub fn read_only(&self) -> BufReadMemlocked {
        BufReadMemlocked(self.0.clone())
    }
}

impl Debug for BufWriteMemlocked {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufWriteMemlocked").finish()
    }
}

impl AsBufRead for BufWriteMemlocked {
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
        let g = self.0.lock();
        g.set_readable();
        ReadGuard(Box::new(X(g)))
    }
}

impl AsBufWrite for BufWriteMemlocked {
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
        let g = self.0.lock();
        g.set_writable();
        WriteGuard(Box::new(X(g)))
    }

    fn read_only(&self) -> BufRead {
        BufRead(BufReadInner::MemlockedDowngrade(self.clone()))
    }
}

#[derive(Debug, Clone)]
enum BufReadInner {
    NoLock(BufReadNoLock),
    NoLockDowngrade(BufWriteNoLock),
    //Memlocked(BufReadMemlocked),
    MemlockedDowngrade(BufWriteMemlocked),
}

impl AsBufRead for BufReadInner {
    fn read_lock(&self) -> ReadGuard<'_> {
        match self {
            Self::NoLock(b) => b.read_lock(),
            Self::NoLockDowngrade(b) => b.read_lock(),
            //Self::Memlocked(b) => b.read_lock(),
            Self::MemlockedDowngrade(b) => b.read_lock(),
        }
    }
}

/// A concrete read-only buffer type that may or may not be memlocked.
#[derive(Debug, Clone)]
pub struct BufRead(BufReadInner);

impl BufRead {
    /// Consruct a new BufRead that is NOT memlocked.
    pub fn new_no_lock(content: &[u8]) -> Self {
        Self(BufReadInner::NoLock(new_buf_read_no_lock(content)))
    }
}

impl AsBufRead for BufRead {
    fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }
}

#[derive(Debug, Clone)]
enum BufWriteInner {
    NoLock(BufWriteNoLock),
    Memlocked(BufWriteMemlocked),
}

impl AsBufRead for BufWriteInner {
    fn read_lock(&self) -> ReadGuard<'_> {
        match self {
            Self::NoLock(b) => b.read_lock(),
            Self::Memlocked(b) => b.read_lock(),
        }
    }
}

impl AsBufWrite for BufWriteInner {
    fn write_lock(&self) -> WriteGuard<'_> {
        match self {
            Self::NoLock(b) => b.write_lock(),
            Self::Memlocked(b) => b.write_lock(),
        }
    }

    fn read_only(&self) -> BufRead {
        match self {
            Self::NoLock(b) => AsBufWrite::read_only(b),
            Self::Memlocked(b) => AsBufWrite::read_only(b),
        }
    }
}

/// A concrete writable buffer type that may or may not be memlocked.
#[derive(Debug, Clone)]
pub struct BufWrite(BufWriteInner);

impl BufWrite {
    /// Consruct a new BufWrite that is NOT memlocked.
    pub fn new_no_lock(size: usize) -> Self {
        Self(BufWriteInner::NoLock(new_buf_write_no_lock(size)))
    }

    /// Construct a new memlocked BufWrite instance.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    pub fn new_memlocked(size: usize) -> SodokenResult<Self> {
        Ok(Self(BufWriteInner::Memlocked(BufWriteMemlocked::new(
            size,
        )?)))
    }
}

impl AsBufRead for BufWrite {
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
