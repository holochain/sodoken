use std::io::{ErrorKind, Result};

/// Locked memory.
pub struct LockedArray<const N: usize>(*mut libc::c_void);

// the sodium_malloc-ed c_void is safe to Send
unsafe impl<const N: usize> Send for LockedArray<N> {}

// note - it might technically be ok it implement Sync,
// but not to lock/unlock it across threads... so we
// need to keep the lock function `&mut self` so the
// Sync wouldn't help usage in any way.

impl<const N: usize> Drop for LockedArray<N> {
    fn drop(&mut self) {
        unsafe {
            libsodium_sys::sodium_free(self.0);
        }
    }
}

impl<const N: usize> LockedArray<N> {
    /// Create a new locked memory buffer.
    pub fn new() -> Result<Self> {
        crate::sodium_init();

        let z = unsafe {
            // sodium_malloc requires memory-aligned sizes,
            // round up to the nearest 8 bytes.
            let align_size = (N + 7) & !7;
            let z = libsodium_sys::sodium_malloc(align_size);
            if z.is_null() {
                return Err(ErrorKind::OutOfMemory.into());
            }
            libsodium_sys::sodium_memzero(z, align_size);
            libsodium_sys::sodium_mprotect_noaccess(z);
            z
        };

        Ok(Self(z))
    }

    /// Get access to this memory.
    pub fn lock(&mut self) -> LockedArrayGuard<'_, N> {
        LockedArrayGuard::new(self)
    }
}

/// Locked memory that is unlocked for access.
pub struct LockedArrayGuard<'g, const N: usize>(&'g mut LockedArray<N>);

impl<'g, const N: usize> LockedArrayGuard<'g, N> {
    fn new(l: &'g mut LockedArray<N>) -> Self {
        unsafe {
            libsodium_sys::sodium_mprotect_readwrite(l.0);
        }
        Self(l)
    }
}

impl<'g, const N: usize> Drop for LockedArrayGuard<'g, N> {
    fn drop(&mut self) {
        unsafe {
            libsodium_sys::sodium_mprotect_noaccess(self.0 .0);
        }
    }
}

impl<'g, const N: usize> std::ops::Deref for LockedArrayGuard<'g, N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        unsafe {
            &*(std::slice::from_raw_parts(self.0 .0 as *const u8, N)[..N]
                .as_ptr() as *const [u8; N])
        }
    }
}

impl<'g, const N: usize> std::ops::DerefMut for LockedArrayGuard<'g, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            &mut *(std::slice::from_raw_parts_mut(self.0 .0 as *mut u8, N)[..N]
                .as_mut_ptr() as *mut [u8; N])
        }
    }
}
