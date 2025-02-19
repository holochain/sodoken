use std::io::{ErrorKind, Result};

/// Locked memory.
pub struct LockedArray(usize, *mut libc::c_void);

// the sodium_malloc-ed c_void is safe to Send
unsafe impl Send for LockedArray {}

// note - it might technically be ok it implement Sync,
// but not to lock/unlock it across threads... so we
// need to keep the lock function `&mut self` so the
// Sync wouldn't help usage in any way.

impl Drop for LockedArray {
    fn drop(&mut self) {
        unsafe {
            libsodium_sys::sodium_free(self.1);
        }
    }
}

impl LockedArray {
    /// Create a new locked memory buffer.
    pub fn new(size: usize) -> Result<Self> {
        crate::sodium_init();

        let z = unsafe {
            // sodium_malloc requires memory-aligned sizes,
            // round up to the nearest 8 bytes.
            let align_size = (size + 7) & !7;
            let z = libsodium_sys::sodium_malloc(align_size);
            if z.is_null() {
                return Err(ErrorKind::OutOfMemory.into());
            }
            libsodium_sys::sodium_memzero(z, align_size);
            libsodium_sys::sodium_mprotect_noaccess(z);
            z
        };

        Ok(Self(size, z))
    }

    /// Get access to this memory.
    pub fn lock(&mut self) -> LockedArrayGuard<'_> {
        LockedArrayGuard::new(self)
    }
}

/// Locked memory that is unlocked for access.
pub struct LockedArrayGuard<'g>(&'g mut LockedArray);

impl<'g> LockedArrayGuard<'g> {
    fn new(l: &'g mut LockedArray) -> Self {
        unsafe {
            libsodium_sys::sodium_mprotect_readwrite(l.1);
        }
        Self(l)
    }
}

impl Drop for LockedArrayGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            libsodium_sys::sodium_mprotect_noaccess(self.0 .1);
        }
    }
}

impl std::ops::Deref for LockedArrayGuard<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.0 .1 as *const u8, self.0 .0) }
    }
}

impl std::ops::DerefMut for LockedArrayGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            std::slice::from_raw_parts_mut(self.0 .1 as *mut u8, self.0 .0)
        }
    }
}

/// Locked memory with a size known at compile time.
pub struct SizedLockedArray<const N: usize>(LockedArray);

impl<const N: usize> SizedLockedArray<N> {
    /// Create a new locked memory buffer.
    pub fn new() -> Result<Self> {
        Ok(Self(LockedArray::new(N)?))
    }

    /// Get access to this memory.
    pub fn lock(&mut self) -> LockedArrayGuardSized<'_, N> {
        LockedArrayGuardSized::new(self)
    }
}

/// Locked memory that is unlocked for access.
pub struct LockedArrayGuardSized<'g, const N: usize>(LockedArrayGuard<'g>);

impl<'g, const N: usize> LockedArrayGuardSized<'g, N> {
    fn new(l: &'g mut SizedLockedArray<N>) -> Self {
        Self(l.0.lock())
    }
}

impl<const N: usize> std::ops::Deref for LockedArrayGuardSized<'_, N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        unsafe {
            &*(std::slice::from_raw_parts(self.0 .0 .1 as *const u8, N)[..N]
                .as_ptr() as *const [u8; N])
        }
    }
}

impl<const N: usize> std::ops::DerefMut for LockedArrayGuardSized<'_, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            &mut *(std::slice::from_raw_parts_mut(self.0 .0 .1 as *mut u8, N)
                [..N]
                .as_mut_ptr() as *mut [u8; N])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_locked_array_as_array() {
        let mut locked = LockedArray::new(32).unwrap();
        locked.lock().copy_from_slice(&[5; 32]);

        fn call_me(input: &[u8]) -> u8 {
            input[0]
        }
        assert_eq!(5, call_me(&*locked.lock()));

        fn call_me_mut(input: &mut [u8]) {
            input[0] = 8;
        }
        call_me_mut(&mut *locked.lock());

        assert_eq!(8, call_me(&*locked.lock()));
    }

    #[test]
    fn use_sized_locked_array_as_array() {
        let mut locked = SizedLockedArray::<32>::new().unwrap();
        locked.lock().copy_from_slice(&[5; 32]);

        fn call_me(input: &[u8; 32]) -> u8 {
            input[0]
        }
        assert_eq!(5, call_me(&*locked.lock()));

        fn call_me_mut(input: &mut [u8; 32]) {
            input[0] = 8;
        }
        call_me_mut(&mut *locked.lock());

        assert_eq!(8, call_me(&*locked.lock()));
    }
}
