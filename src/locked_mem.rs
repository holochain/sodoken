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

impl From<Vec<u8>> for LockedArray {
    fn from(s: Vec<u8>) -> Self {
        let s = zeroize::Zeroizing::new(s);

        let mut out = Self::new(s.len()).unwrap();
        out.lock().copy_from_slice(s.as_slice());

        out
    }
}

impl From<Box<[u8]>> for LockedArray {
    fn from(value: Box<[u8]>) -> Self {
        let value = zeroize::Zeroizing::new(value);

        let mut out = Self::new(value.len()).unwrap();
        out.lock().copy_from_slice(value.as_ref());

        out
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
    pub fn lock(&mut self) -> SizedLockedArrayGuard<'_, N> {
        SizedLockedArrayGuard::new(self)
    }
}

/// Locked memory that is unlocked for access.
pub struct SizedLockedArrayGuard<'g, const N: usize>(LockedArrayGuard<'g>);

impl<'g, const N: usize> SizedLockedArrayGuard<'g, N> {
    fn new(l: &'g mut SizedLockedArray<N>) -> Self {
        Self(l.0.lock())
    }
}

impl<const N: usize> std::ops::Deref for SizedLockedArrayGuard<'_, N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        unsafe {
            &*(std::slice::from_raw_parts(self.0 .0 .1 as *const u8, N)[..N]
                .as_ptr() as *const [u8; N])
        }
    }
}

impl<const N: usize> std::ops::DerefMut for SizedLockedArrayGuard<'_, N> {
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

    // This test relies on being able to read back memory that has been unallocated.
    // If this breaks, it may be best to remove it.
    #[test]
    fn clears_input_buffer_from_vec() {
        let mut input = vec![1, 2, 3];
        input.resize(3, 0);

        let ptr = input.as_ptr();

        let mut locked = LockedArray::from(input);

        let vec = unsafe { Vec::from_raw_parts(ptr as *mut u8, 3, 3) };

        assert_eq!(vec, vec![0, 0, 0]);
        std::mem::forget(vec);

        assert_eq!(&*locked.lock(), &[1, 2, 3]);
    }

    // This test relies on being able to read back memory that has been unallocated.
    // If this breaks, it may be best to remove it.
    #[test]
    fn clears_input_buffer_from_box() {
        let input: Box<[u8]> = vec![1, 2, 3].into();

        let ptr = input.as_ptr();

        let mut locked = LockedArray::from(input);

        let vec = unsafe { Box::from_raw(ptr as *mut [u8; 3]) };

        assert_eq!(vec, Box::new([0, 0, 0]));
        std::mem::forget(vec);

        assert_eq!(&*locked.lock(), &[1, 2, 3]);
    }
}
