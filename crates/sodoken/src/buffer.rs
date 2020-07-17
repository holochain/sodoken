use crate::*;
use std::{
    borrow::{Borrow, BorrowMut},
    convert::{AsMut, AsRef},
    fmt::{Debug, Formatter},
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
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

/// A buffer represents an array of bytes that may or may not be memory locked.
pub trait AsBuffer: 'static + Debug + Send + Sync {
    /// Deep clone the actual bytes of this buffer.
    /// The type (memlocked or not) will be retained.
    /// Not to be confused with "clone" on the Buffer struct,
    /// which just bumps a refcount.
    fn deep_clone(&self) -> SodokenResult<Buffer>;

    /// Obtain read access to the underlying buffer.
    fn read_lock(&self) -> ReadGuard<'_>;

    /// Obtain write access to the underlying buffer.
    fn write_lock(&self) -> WriteGuard<'_>;
}

/// Concrete newtype to abstract away dealing with the dynamic buffer type.
#[derive(Debug, Clone)]
pub struct Buffer(pub Arc<dyn 'static + AsBuffer>);

impl From<Vec<u8>> for Buffer {
    fn from(o: Vec<u8>) -> Self {
        o.into_boxed_slice().into()
    }
}

impl From<Box<[u8]>> for Buffer {
    fn from(o: Box<[u8]>) -> Self {
        struct XX(RwLock<Box<[u8]>>);
        impl Debug for XX {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("SodokenBuffer").finish()
            }
        }
        impl AsBuffer for XX {
            fn deep_clone(&self) -> SodokenResult<Buffer> {
                let g = self.0.read().unwrap();
                let g = g.deref();
                let out = g.clone();
                Ok(Buffer(Arc::new(XX(RwLock::new(out)))))
            }

            fn read_lock(&self) -> ReadGuard<'_> {
                struct XX<'a>(RwLockReadGuard<'a, Box<[u8]>>);
                impl Deref for XX<'_> {
                    type Target = [u8];
                    fn deref(&self) -> &Self::Target {
                        &self.0
                    }
                }
                impl AsRef<[u8]> for XX<'_> {
                    fn as_ref(&self) -> &[u8] {
                        &self.0
                    }
                }
                impl Borrow<[u8]> for XX<'_> {
                    fn borrow(&self) -> &[u8] {
                        &self.0
                    }
                }
                impl<'a> AsRead<'a> for XX<'a> {}
                let x = Box::new(XX(self.0.read().unwrap()));
                ReadGuard(x)
            }

            fn write_lock(&self) -> WriteGuard<'_> {
                struct XX<'a>(RwLockWriteGuard<'a, Box<[u8]>>);
                impl Deref for XX<'_> {
                    type Target = [u8];
                    fn deref(&self) -> &Self::Target {
                        &self.0
                    }
                }
                impl DerefMut for XX<'_> {
                    fn deref_mut(&mut self) -> &mut Self::Target {
                        &mut self.0
                    }
                }
                impl AsRef<[u8]> for XX<'_> {
                    fn as_ref(&self) -> &[u8] {
                        &self.0
                    }
                }
                impl AsMut<[u8]> for XX<'_> {
                    fn as_mut(&mut self) -> &mut [u8] {
                        &mut self.0
                    }
                }
                impl Borrow<[u8]> for XX<'_> {
                    fn borrow(&self) -> &[u8] {
                        &self.0
                    }
                }
                impl BorrowMut<[u8]> for XX<'_> {
                    fn borrow_mut(&mut self) -> &mut [u8] {
                        &mut self.0
                    }
                }
                impl<'a> AsRead<'a> for XX<'a> {}
                impl<'a> AsWrite<'a> for XX<'a> {}
                let x = Box::new(XX(self.0.write().unwrap()));
                WriteGuard(x)
            }
        }
        Buffer(Arc::new(XX(RwLock::new(o))))
    }
}

impl Buffer {
    /// Create a new buffer instance using unlocked memory.
    /// No protection will be added, you should consider `buffer_new_memlocked`
    /// for storing private keys and data.
    pub fn new(size: usize) -> Buffer {
        vec![0; size].into()
    }

    /// Create a new buffer instance using locked memory.
    /// This is a finite resource, so don't go too crazy.
    /// But it is worth doing for things like private keys so they don't get
    /// swapped to disk in plaintext.
    pub fn new_memlocked(size: usize) -> SodokenResult<Buffer> {
        buffer_new_memlocked(size)
    }

    /// Deep clone the actual bytes of this buffer.
    /// The type (memlocked or not) will be retained.
    /// Not to be confused with "clone" on the Buffer struct,
    /// which just bumps a refcount.
    pub fn deep_clone(&self) -> SodokenResult<Buffer> {
        self.0.deep_clone()
    }

    /// Obtain read access to the underlying buffer.
    pub fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }

    /// Obtain write access to the underlying buffer.
    pub fn write_lock(&self) -> WriteGuard<'_> {
        self.0.write_lock()
    }
}

impl AsBuffer for Buffer {
    fn deep_clone(&self) -> SodokenResult<Buffer> {
        self.0.deep_clone()
    }

    fn read_lock(&self) -> ReadGuard<'_> {
        self.0.read_lock()
    }

    fn write_lock(&self) -> WriteGuard<'_> {
        self.0.write_lock()
    }
}

fn buffer_new_memlocked(size: usize) -> SodokenResult<Buffer> {
    struct XX(Mutex<safe::s3buf::S3Buf>);
    impl Debug for XX {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SodokenBufferMemlocked").finish()
        }
    }
    impl AsBuffer for XX {
        fn deep_clone(&self) -> SodokenResult<Buffer> {
            let g = self.0.lock().unwrap();
            let g = g.deref();
            let mut out = safe::s3buf::S3Buf::new(g.s)?;
            g.set_readable();
            out.set_writable();
            out.deref_mut().copy_from_slice(g.deref());
            g.set_no_access();
            out.set_no_access();
            Ok(Buffer(Arc::new(XX(Mutex::new(out)))))
        }

        fn read_lock(&self) -> ReadGuard<'_> {
            struct XX<'a>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl Drop for XX<'_> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl Deref for XX<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl AsRef<[u8]> for XX<'_> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl Borrow<[u8]> for XX<'_> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl<'a> AsRead<'a> for XX<'a> {}
            let g = self.0.lock().unwrap();
            g.set_readable();
            ReadGuard(Box::new(XX(g)))
        }

        fn write_lock(&self) -> WriteGuard<'_> {
            struct XX<'a>(MutexGuard<'a, safe::s3buf::S3Buf>);
            impl Drop for XX<'_> {
                fn drop(&mut self) {
                    self.0.set_no_access();
                }
            }
            impl Deref for XX<'_> {
                type Target = [u8];
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl DerefMut for XX<'_> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.0
                }
            }
            impl AsRef<[u8]> for XX<'_> {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }
            impl AsMut<[u8]> for XX<'_> {
                fn as_mut(&mut self) -> &mut [u8] {
                    &mut self.0
                }
            }
            impl Borrow<[u8]> for XX<'_> {
                fn borrow(&self) -> &[u8] {
                    &self.0
                }
            }
            impl BorrowMut<[u8]> for XX<'_> {
                fn borrow_mut(&mut self) -> &mut [u8] {
                    &mut self.0
                }
            }
            impl<'a> AsRead<'a> for XX<'a> {}
            impl<'a> AsWrite<'a> for XX<'a> {}
            let g = self.0.lock().unwrap();
            g.set_writable();
            WriteGuard(Box::new(XX(g)))
        }
    }
    Ok(Buffer(Arc::new(XX(Mutex::new(safe::s3buf::S3Buf::new(
        size,
    )?)))))
}
