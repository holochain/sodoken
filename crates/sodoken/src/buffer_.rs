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

/// A concrete read-only buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufRead(pub Arc<dyn AsBufRead>);

impl From<BufWrite> for BufRead {
    fn from(b: BufWrite) -> Self {
        b.to_read()
    }
}

impl<const S: usize> From<BufReadSized<S>> for BufRead {
    fn from(b: BufReadSized<S>) -> Self {
        b.to_read_unsized()
    }
}

impl<const S: usize> From<BufWriteSized<S>> for BufRead {
    fn from(b: BufWriteSized<S>) -> Self {
        b.to_read_unsized()
    }
}

impl<'a> From<&'a [u8]> for BufRead {
    fn from(b: &'a [u8]) -> Self {
        b.to_vec().into()
    }
}

impl From<Vec<u8>> for BufRead {
    fn from(b: Vec<u8>) -> Self {
        b.into_boxed_slice().into()
    }
}

impl From<Box<[u8]>> for BufRead {
    fn from(b: Box<[u8]>) -> Self {
        Self(Arc::new(b))
    }
}

impl BufRead {
    /// Consruct a new BufRead that is NOT mem_locked.
    pub fn new_no_lock(content: &[u8]) -> Self {
        content.to_vec().into()
    }

    /// The length of this buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is this buffer empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Obtain read access to the underlying buffer.
    pub fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }
}

/// A concrete sized read-only buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufReadSized<const N: usize>(pub Arc<dyn AsBufReadSized<N>>);

impl<const S: usize> From<BufWriteSized<S>> for BufReadSized<S> {
    fn from(b: BufWriteSized<S>) -> Self {
        b.to_read_sized()
    }
}

impl<const N: usize> From<[u8; N]> for BufReadSized<N> {
    fn from(b: [u8; N]) -> Self {
        Self(Arc::new(b))
    }
}

impl<'a, const N: usize> From<&'a [u8]> for BufReadSized<N> {
    fn from(b: &'a [u8]) -> Self {
        // the arrayref crate doesn't work with const generics
        // this code is just coppied / modified to work
        #[inline]
        unsafe fn as_array<const N: usize>(slice: &[u8]) -> &[u8; N] {
            &*(slice.as_ptr() as *const [_; N])
        }
        let slice = &b[0..N];
        let b = *unsafe { as_array(slice) };
        Self(Arc::new(b))
    }
}

impl<const N: usize> BufReadSized<N> {
    /// Construct a new BufReadSized that is NOT mem_locked.
    pub fn new_no_lock(content: [u8; N]) -> BufReadSized<N> {
        content.into()
    }

    /// The length of this buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is this buffer empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Obtain read access to the underlying buffer.
    pub fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }

    /// Obtain read access to the underlying buffer.
    pub fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
        self.0.read_lock_sized()
    }

    /// Convert to an unsized BufRead instance
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn to_read_unsized(&self) -> BufRead {
        self.0.clone().into_read_unsized()
    }
}

/// A concrete writable buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufWrite(pub Arc<dyn AsBufWrite>);

impl<const S: usize> From<BufWriteSized<S>> for BufWrite {
    fn from(b: BufWriteSized<S>) -> Self {
        b.to_write_unsized()
    }
}

impl From<Vec<u8>> for BufWrite {
    fn from(b: Vec<u8>) -> Self {
        Self(Arc::new(RwLock::new(b)))
    }
}

impl From<Box<[u8]>> for BufWrite {
    fn from(b: Box<[u8]>) -> Self {
        Self(Arc::new(RwLock::new(b)))
    }
}

impl BufWrite {
    /// Construct a new unbound BufWrite that is NOT mem_locked
    /// and initially has zero length.
    pub fn new_unbound_no_lock() -> Self {
        Vec::new().into()
    }

    /// Construct a new BufWrite that is NOT mem_locked.
    pub fn new_no_lock(size: usize) -> Self {
        vec![0; size].into_boxed_slice().into()
    }

    /// Construct a new BufWrite that IS mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    pub fn new_mem_locked(size: usize) -> SodokenResult<Self> {
        Ok(Self(Arc::new(BufWriteMemLocked::new(size)?)))
    }

    /// The length of this buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is this buffer empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Obtain read access to the underlying buffer.
    pub fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }

    /// Obtain write access to the underlying buffer.
    pub fn write_lock(&self) -> WriteGuard<'_> {
        self.0.write_lock()
    }

    /// Downgrade this to a read-only reference
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn to_read(&self) -> BufRead {
        self.0.clone().into_read()
    }

    /// Transform this buffer into an extendable type.
    pub fn to_extend(&self) -> BufExtend {
        self.0.clone().into_extend()
    }
}

/// A concrete sized writable buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufWriteSized<const N: usize>(pub Arc<dyn AsBufWriteSized<N>>);

impl<const N: usize> From<[u8; N]> for BufWriteSized<N> {
    fn from(b: [u8; N]) -> Self {
        Self(Arc::new(RwLock::new(b)))
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

    /// The length of this buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is this buffer empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Obtain read access to the underlying buffer.
    pub fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }

    /// Obtain read access to the underlying buffer.
    pub fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
        self.0.read_lock_sized()
    }

    /// Convert to an unsized BufRead instance
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn to_read_unsized(&self) -> BufRead {
        self.0.clone().into_read_unsized()
    }

    /// Obtain write access to the underlying buffer.
    pub fn write_lock(&self) -> WriteGuard<'_> {
        self.0.write_lock()
    }

    /// Downgrade this to a read-only reference
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn to_read(&self) -> BufRead {
        self.0.clone().into_read()
    }

    /// Obtain write access to the underlying buffer.
    pub fn write_lock_sized(&self) -> WriteGuardSized<'_, N> {
        self.0.write_lock_sized()
    }

    /// Downgrade this to a read-only reference
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn to_read_sized(&self) -> BufReadSized<N> {
        self.0.clone().into_read_sized()
    }

    /// Convert to an unsized BufWrite instance
    /// without cloning internal data
    /// and without changing memory locking strategy.
    pub fn to_write_unsized(&self) -> BufWrite {
        self.0.clone().into_write_unsized()
    }
}

/// A concrete extendable buffer type that may or may not be mem_locked.
#[derive(Debug, Clone)]
pub struct BufExtend(pub Arc<dyn AsBufExtend>);

impl From<BufWrite> for BufExtend {
    fn from(b: BufWrite) -> Self {
        b.to_extend()
    }
}

impl BufExtend {
    /// Obtain access to extend the underlying buffer.
    pub fn extend_lock(&self) -> ExtendGuard<'_> {
        self.0.extend_lock()
    }
}

/// Additional types related to working with buffers.
pub mod buffer {
    use super::*;

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

    /// Indicates we can append bytes without pre-initializing them.
    pub trait AsExtendMut<'a>: 'a {
        /// # Safety
        ///
        /// this is unsafe because the process could potentially
        /// - read uninitialized data from the returned slice
        /// - or fail to initialize the data in the returned slice
        unsafe fn unsafe_extend_mut(
            &mut self,
            len: usize,
        ) -> SodokenResult<&mut [u8]>;
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

    /// An extend guard, indicating we have gained access to extend the buffer.
    pub struct ExtendGuard<'a>(pub Box<dyn 'a + AsExtendMut<'a>>);

    impl<'a> ExtendGuard<'a> {
        /// # Safety
        ///
        /// this is unsafe because the process could potentially
        /// - read uninitialized data from the returned slice
        /// - or fail to initialize the data in the returned slice
        pub unsafe fn unsafe_extend_mut(
            &mut self,
            len: usize,
        ) -> SodokenResult<&mut [u8]> {
            self.0.unsafe_extend_mut(len)
        }
    }

    /// A readable buffer that may or may not be mem_locked.
    pub trait AsBufRead: 'static + Debug + Send + Sync {
        /// The length of this buffer.
        fn len(&self) -> usize;

        /// Is this buffer empty?
        fn is_empty(&self) -> bool;

        /// Obtain read access to the underlying buffer.
        fn read_lock(&self) -> ReadGuard<'_>;
    }

    impl AsBufRead for Box<[u8]> {
        fn len(&self) -> usize {
            self.as_ref().len()
        }

        fn is_empty(&self) -> bool {
            self.as_ref().is_empty()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(&'a [u8]);
            impl<'a> std::ops::Deref for X<'a> {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<'a> AsRef<[u8]> for X<'a> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> Borrow<[u8]> for X<'a> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            ReadGuard(Box::new(X(&self[..])))
        }
    }

    impl<const N: usize> AsBufRead for [u8; N] {
        fn len(&self) -> usize {
            self.as_ref().len()
        }

        fn is_empty(&self) -> bool {
            self.as_ref().is_empty()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(&'a [u8]);
            impl<'a> std::ops::Deref for X<'a> {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<'a> AsRef<[u8]> for X<'a> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> Borrow<[u8]> for X<'a> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            ReadGuard(Box::new(X(&self[..])))
        }
    }

    impl AsBufRead for RwLock<Box<[u8]>> {
        fn len(&self) -> usize {
            self.read().len()
        }

        fn is_empty(&self) -> bool {
            self.read().is_empty()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(RwLockReadGuard<'a, Box<[u8]>>);
            impl<'a> std::ops::Deref for X<'a> {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<'a> AsRef<[u8]> for X<'a> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> Borrow<[u8]> for X<'a> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            ReadGuard(Box::new(X(self.read())))
        }
    }

    impl AsBufRead for RwLock<Vec<u8>> {
        fn len(&self) -> usize {
            self.read().len()
        }

        fn is_empty(&self) -> bool {
            self.read().is_empty()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a>(RwLockReadGuard<'a, Vec<u8>>);
            impl<'a> std::ops::Deref for X<'a> {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<'a> AsRef<[u8]> for X<'a> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> Borrow<[u8]> for X<'a> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            ReadGuard(Box::new(X(self.read())))
        }
    }

    impl<const N: usize> AsBufRead for RwLock<[u8; N]> {
        fn len(&self) -> usize {
            self.read().len()
        }

        fn is_empty(&self) -> bool {
            self.read().is_empty()
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct X<'a, const N: usize>(RwLockReadGuard<'a, [u8; N]>);
            impl<'a, const N: usize> std::ops::Deref for X<'a, N> {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    &self.0[..]
                }
            }
            impl<'a, const N: usize> AsRef<[u8]> for X<'a, N> {
                fn as_ref(&self) -> &[u8] {
                    &self.0[..]
                }
            }
            impl<'a, const N: usize> Borrow<[u8]> for X<'a, N> {
                fn borrow(&self) -> &[u8] {
                    &self.0[..]
                }
            }
            impl<'a, const N: usize> AsRead<'a> for X<'a, N> {}
            ReadGuard(Box::new(X(self.read())))
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
        fn into_read_unsized(self: Arc<Self>) -> BufRead;
    }

    impl<const N: usize> AsBufReadSized<N> for [u8; N] {
        fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
            struct X<'a, const N: usize>(&'a [u8; N]);
            impl<'a, const N: usize> std::ops::Deref for X<'a, N> {
                type Target = [u8; N];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<'a, const N: usize> AsRef<[u8; N]> for X<'a, N> {
                fn as_ref(&self) -> &[u8; N] {
                    &self.0
                }
            }
            impl<'a, const N: usize> Borrow<[u8; N]> for X<'a, N> {
                fn borrow(&self) -> &[u8; N] {
                    &self.0
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            ReadGuardSized(Box::new(X(&self)))
        }

        fn into_read_unsized(self: Arc<Self>) -> BufRead {
            BufRead(self)
        }
    }

    impl<const N: usize> AsBufReadSized<N> for RwLock<[u8; N]> {
        fn read_lock_sized(&self) -> ReadGuardSized<'_, N> {
            struct X<'a, const N: usize>(RwLockReadGuard<'a, [u8; N]>);
            impl<'a, const N: usize> std::ops::Deref for X<'a, N> {
                type Target = [u8; N];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<'a, const N: usize> AsRef<[u8; N]> for X<'a, N> {
                fn as_ref(&self) -> &[u8; N] {
                    &self.0
                }
            }
            impl<'a, const N: usize> Borrow<[u8; N]> for X<'a, N> {
                fn borrow(&self) -> &[u8; N] {
                    &self.0
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            ReadGuardSized(Box::new(X(self.read())))
        }

        fn into_read_unsized(self: Arc<Self>) -> BufRead {
            BufRead(self)
        }
    }

    /// A writable buffer that may or may not be mem_locked.
    pub trait AsBufWrite: AsBufRead {
        /// Obtain write access to the underlying buffer.
        fn write_lock(&self) -> WriteGuard<'_>;

        /// Downgrade this to a read-only reference
        /// without cloning internal data
        /// and without changing memory locking strategy.
        fn into_read(self: Arc<Self>) -> BufRead;

        /// Transform this buffer into an extendable type.
        fn into_extend(self: Arc<Self>) -> BufExtend;
    }

    /// a fake extend guard that operates over a whole write guard
    fn write_guard_to_extend_guard(g: WriteGuard<'_>) -> ExtendGuard<'_> {
        // this lock simulates an extendable buffer
        // it's not actually unsafe, and we get no performance benefits
        // because the memory is actually pre-initialized
        struct G<'a>(WriteGuard<'a>, usize);
        impl<'a> AsExtendMut<'a> for G<'a> {
            unsafe fn unsafe_extend_mut(
                &mut self,
                len: usize,
            ) -> SodokenResult<&mut [u8]> {
                let cur_len = self.1;
                let new_len = cur_len + len;
                if new_len > self.0.len() {
                    return Err(SodokenError::WriteOverflow);
                }
                self.1 = new_len;
                Ok(&mut self.0[cur_len..new_len])
            }
        }
        ExtendGuard(Box::new(G(g, 0)))
    }

    impl AsBufWrite for RwLock<Box<[u8]>> {
        fn write_lock(&self) -> WriteGuard<'_> {
            struct X<'a>(RwLockWriteGuard<'a, Box<[u8]>>);
            impl<'a> std::ops::Deref for X<'a> {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<'a> std::ops::DerefMut for X<'a> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.0
                }
            }
            impl<'a> AsRef<[u8]> for X<'a> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsMut<[u8]> for X<'a> {
                fn as_mut(&mut self) -> &mut [u8] {
                    &mut self.0
                }
            }
            impl<'a> Borrow<[u8]> for X<'a> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> BorrowMut<[u8]> for X<'a> {
                fn borrow_mut(&mut self) -> &mut [u8] {
                    &mut self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            impl<'a> AsWrite<'a> for X<'a> {}
            WriteGuard(Box::new(X(self.write())))
        }

        fn into_read(self: Arc<Self>) -> BufRead {
            BufRead(self)
        }

        fn into_extend(self: Arc<Self>) -> BufExtend {
            BufExtend(self)
        }
    }

    impl AsBufWrite for RwLock<Vec<u8>> {
        fn write_lock(&self) -> WriteGuard<'_> {
            struct X<'a>(RwLockWriteGuard<'a, Vec<u8>>);
            impl<'a> std::ops::Deref for X<'a> {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<'a> std::ops::DerefMut for X<'a> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.0
                }
            }
            impl<'a> AsRef<[u8]> for X<'a> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsMut<[u8]> for X<'a> {
                fn as_mut(&mut self) -> &mut [u8] {
                    &mut self.0
                }
            }
            impl<'a> Borrow<[u8]> for X<'a> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> BorrowMut<[u8]> for X<'a> {
                fn borrow_mut(&mut self) -> &mut [u8] {
                    &mut self.0
                }
            }
            impl<'a> AsRead<'a> for X<'a> {}
            impl<'a> AsWrite<'a> for X<'a> {}
            WriteGuard(Box::new(X(self.write())))
        }

        fn into_read(self: Arc<Self>) -> BufRead {
            BufRead(self)
        }

        fn into_extend(self: Arc<Self>) -> BufExtend {
            BufExtend(self)
        }
    }

    impl<const N: usize> AsBufWrite for RwLock<[u8; N]> {
        fn write_lock(&self) -> WriteGuard<'_> {
            struct X<'a, const N: usize>(RwLockWriteGuard<'a, [u8; N]>);
            impl<'a, const N: usize> std::ops::Deref for X<'a, N> {
                type Target = [u8];

                fn deref(&self) -> &Self::Target {
                    &*self.0
                }
            }
            impl<'a, const N: usize> std::ops::DerefMut for X<'a, N> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut *self.0
                }
            }
            impl<'a, const N: usize> AsRef<[u8]> for X<'a, N> {
                fn as_ref(&self) -> &[u8] {
                    &*self.0
                }
            }
            impl<'a, const N: usize> AsMut<[u8]> for X<'a, N> {
                fn as_mut(&mut self) -> &mut [u8] {
                    &mut *self.0
                }
            }
            impl<'a, const N: usize> Borrow<[u8]> for X<'a, N> {
                fn borrow(&self) -> &[u8] {
                    &*self.0
                }
            }
            impl<'a, const N: usize> BorrowMut<[u8]> for X<'a, N> {
                fn borrow_mut(&mut self) -> &mut [u8] {
                    &mut *self.0
                }
            }
            impl<'a, const N: usize> AsRead<'a> for X<'a, N> {}
            impl<'a, const N: usize> AsWrite<'a> for X<'a, N> {}
            WriteGuard(Box::new(X(self.write())))
        }

        fn into_read(self: Arc<Self>) -> BufRead {
            BufRead(self)
        }

        fn into_extend(self: Arc<Self>) -> BufExtend {
            BufExtend(self)
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
        fn into_read_sized(self: Arc<Self>) -> BufReadSized<N>;

        /// Convert to an unsized BufWrite instance
        /// without cloning internal data
        /// and without changing memory locking strategy.
        fn into_write_unsized(self: Arc<Self>) -> BufWrite;
    }

    impl<const N: usize> AsBufWriteSized<N> for RwLock<[u8; N]> {
        fn write_lock_sized(&self) -> WriteGuardSized<'_, N> {
            struct X<'a, const N: usize>(RwLockWriteGuard<'a, [u8; N]>);
            impl<'a, const N: usize> std::ops::Deref for X<'a, N> {
                type Target = [u8; N];

                fn deref(&self) -> &Self::Target {
                    &*self.0
                }
            }
            impl<'a, const N: usize> std::ops::DerefMut for X<'a, N> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut *self.0
                }
            }
            impl<'a, const N: usize> AsRef<[u8; N]> for X<'a, N> {
                fn as_ref(&self) -> &[u8; N] {
                    &*self.0
                }
            }
            impl<'a, const N: usize> AsMut<[u8; N]> for X<'a, N> {
                fn as_mut(&mut self) -> &mut [u8; N] {
                    &mut *self.0
                }
            }
            impl<'a, const N: usize> Borrow<[u8; N]> for X<'a, N> {
                fn borrow(&self) -> &[u8; N] {
                    &*self.0
                }
            }
            impl<'a, const N: usize> BorrowMut<[u8; N]> for X<'a, N> {
                fn borrow_mut(&mut self) -> &mut [u8; N] {
                    &mut *self.0
                }
            }
            impl<'a, const N: usize> AsReadSized<'a, N> for X<'a, N> {}
            impl<'a, const N: usize> AsWriteSized<'a, N> for X<'a, N> {}
            WriteGuardSized(Box::new(X(self.write())))
        }

        fn into_read_sized(self: Arc<Self>) -> BufReadSized<N> {
            BufReadSized(self)
        }

        fn into_write_unsized(self: Arc<Self>) -> BufWrite {
            BufWrite(self)
        }
    }

    /// A buffer that may be appended to and may or may not be mem_locked.
    pub trait AsBufExtend: 'static + Debug + Send + Sync {
        /// Obtain access to extend the underlying buffer.
        /// Warning: Depending on the underlying data type,
        /// each new ExtendGuard could be a new cursor... i.e.
        /// pulling a new extend lock could overwrite previous data.
        fn extend_lock(&self) -> ExtendGuard<'_>;
    }

    impl AsBufExtend for RwLock<Box<[u8]>> {
        fn extend_lock(&self) -> ExtendGuard<'_> {
            write_guard_to_extend_guard(self.write_lock())
        }
    }

    impl<const N: usize> AsBufExtend for RwLock<[u8; N]> {
        fn extend_lock(&self) -> ExtendGuard<'_> {
            write_guard_to_extend_guard(self.write_lock())
        }
    }

    impl AsBufExtend for RwLock<Vec<u8>> {
        fn extend_lock(&self) -> ExtendGuard<'_> {
            struct X<'a>(RwLockWriteGuard<'a, Vec<u8>>);
            impl<'a> AsExtendMut<'a> for X<'a> {
                unsafe fn unsafe_extend_mut(
                    &mut self,
                    len: usize,
                ) -> SodokenResult<&mut [u8]> {
                    let cur_len = self.0.len();
                    let new_len = cur_len + len;
                    self.0.reserve(len);
                    // *this* is actually unsafe
                    // we're giving potential access to uninitialized data here
                    self.0.set_len(new_len);
                    // and here
                    Ok(&mut self.0[cur_len..new_len])
                }
            }
            ExtendGuard(Box::new(X(self.write())))
        }
    }

    /// This read-only buffer type is mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    pub struct BufReadMemLocked(Mutex<safe::s3buf::S3Buf>);

    impl Debug for BufReadMemLocked {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BufReadMemLocked").finish()
        }
    }

    impl AsBufRead for BufReadMemLocked {
        fn len(&self) -> usize {
            self.0.lock().len()
        }

        fn is_empty(&self) -> bool {
            self.len() == 0
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
    pub struct BufReadMemLockedSized<const N: usize>(Mutex<safe::s3buf::S3Buf>);

    impl<const N: usize> Debug for BufReadMemLockedSized<N> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BufReadMemLocked").finish()
        }
    }

    impl<const N: usize> AsBufRead for BufReadMemLockedSized<N> {
        fn len(&self) -> usize {
            self.0.lock().len()
        }

        fn is_empty(&self) -> bool {
            self.len() == 0
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

        fn into_read_unsized(self: Arc<Self>) -> BufRead {
            BufRead(self)
        }
    }

    /// This writable buffer type is mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    pub struct BufWriteMemLocked(Mutex<safe::s3buf::S3Buf>);

    impl BufWriteMemLocked {
        /// Construct a new writable, mem_locked buffer.
        /// Use this for passwords / private keys, etc, but NOT everything,
        /// locked memory is a finite resource.
        pub fn new(size: usize) -> SodokenResult<Self> {
            Ok(Self(Mutex::new(safe::s3buf::S3Buf::new(size)?)))
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

        fn is_empty(&self) -> bool {
            self.len() == 0
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

        fn into_read(self: Arc<Self>) -> BufRead {
            BufRead(self)
        }

        fn into_extend(self: Arc<Self>) -> BufExtend {
            BufExtend(self)
        }
    }

    impl AsBufExtend for BufWriteMemLocked {
        fn extend_lock(&self) -> ExtendGuard<'_> {
            write_guard_to_extend_guard(self.write_lock())
        }
    }

    /// This writable buffer type is mem_locked.
    /// Use this for passwords / private keys, etc, but NOT everything,
    /// locked memory is a finite resource.
    pub struct BufWriteMemLockedSized<const N: usize>(
        Mutex<safe::s3buf::S3Buf>,
    );

    impl<const N: usize> BufWriteMemLockedSized<N> {
        /// Construct a new writable, mem_locked buffer.
        /// Use this for passwords / private keys, etc, but NOT everything,
        /// locked memory is a finite resource.
        pub fn new() -> SodokenResult<Self> {
            Ok(Self(Mutex::new(safe::s3buf::S3Buf::new(N)?)))
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

        fn is_empty(&self) -> bool {
            self.len() == 0
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

        fn into_read_unsized(self: Arc<Self>) -> BufRead {
            BufRead(self)
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

        fn into_read(self: Arc<Self>) -> BufRead {
            BufRead(self)
        }

        fn into_extend(self: Arc<Self>) -> BufExtend {
            BufExtend(self)
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

        fn into_read_sized(self: Arc<Self>) -> BufReadSized<N> {
            BufReadSized(self)
        }

        fn into_write_unsized(self: Arc<Self>) -> BufWrite {
            BufWrite(self)
        }
    }

    impl<const N: usize> AsBufExtend for BufWriteMemLockedSized<N> {
        fn extend_lock(&self) -> ExtendGuard<'_> {
            write_guard_to_extend_guard(self.write_lock())
        }
    }
}
use buffer::*;
