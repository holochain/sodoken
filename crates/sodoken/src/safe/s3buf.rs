#![allow(dead_code)]
//! These buffer-related invocations are interrelated.
//! Evaluate unsafe blocks in the context of all other calls in this module.

use crate::*;
use libc::c_void;

#[derive(PartialEq)]
enum ProtectState {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

/// internal Safe-Sodium-Secure Buffer
pub(crate) struct S3Buf {
    z: *mut c_void,
    pub(crate) s: usize,
    p: std::cell::RefCell<ProtectState>,
}

// the sodium_malloc-ed c_void is safe to Send
unsafe impl Send for S3Buf {}

// note - it is *not* ok to implement Sync

impl Drop for S3Buf {
    fn drop(&mut self) {
        // sodium_free will zero the memory in the buffer
        // and unlock the memory.
        //
        // INVARIANTS:
        //   - sodium_init() was called (enforced by plugin system)
        //   - must be called on memory allocated by sodium_malloc (or NULL)
        unsafe {
            libsodium_sys::sodium_free(self.z);
        }
    }
}

impl S3Buf {
    /// internal Safe-Sodium-Secure Buffer constructor
    pub(crate) fn new(size: usize) -> SodokenResult<Self> {
        // sodium_malloc:
        //   - allocates the given size of memory
        //   - fills it with 0xdb bytes
        //   - puts guard pages around it
        //   - can error if it cannot allocate
        //
        // INVARIANTS:
        //   - sodium_init() was called (enforced by SODIUM_INIT)
        //   - memory-aligned size
        assert!(*SODIUM_INIT);
        let z = unsafe {
            // sodium_malloc requires memory-aligned sizes,
            // round up to the nearest 8 bytes.
            let align_size = (size + 7) & !7;
            let z = libsodium_sys::sodium_malloc(align_size);
            if z.is_null() {
                return Err(SodokenError::AllocationFailed);
            }
            libsodium_sys::sodium_memzero(z, align_size);
            libsodium_sys::sodium_mprotect_noaccess(z);
            z
        };

        Ok(S3Buf {
            z,
            s: size,
            p: std::cell::RefCell::new(ProtectState::NoAccess),
        })
    }

    /// len
    pub(crate) fn len(&self) -> usize {
        self.s
    }

    /// adjust the memory protection for NO ACCESS
    pub(crate) fn set_no_access(&self) {
        if *self.p.borrow() == ProtectState::NoAccess {
            panic!("already no access... bad logic");
        }

        // INVARIANT - z was allocated with sodium_malloc
        unsafe {
            libsodium_sys::sodium_mprotect_noaccess(self.z);
        }

        *self.p.borrow_mut() = ProtectState::NoAccess;
    }

    /// adjust the memory protection for READ ACCESS
    pub(crate) fn set_readable(&self) {
        if *self.p.borrow() != ProtectState::NoAccess {
            panic!("not no access... bad logic");
        }

        // INVARIANT - z was allocated with sodium_malloc
        unsafe {
            libsodium_sys::sodium_mprotect_readonly(self.z);
        }

        *self.p.borrow_mut() = ProtectState::ReadOnly;
    }

    /// adjust the memory protection for READ+WRITE ACCESS
    pub(crate) fn set_writable(&self) {
        if *self.p.borrow() != ProtectState::NoAccess {
            panic!("not no access... bad logic");
        }

        // INVARIANT - z was allocated with sodium_malloc
        unsafe {
            libsodium_sys::sodium_mprotect_readwrite(self.z);
        }

        *self.p.borrow_mut() = ProtectState::ReadWrite;
    }

    /// as a slice
    pub(crate) fn as_slice(&self) -> &[u8] {
        if *self.p.borrow() == ProtectState::NoAccess {
            panic!("Deref, but state is NoAccess");
        }

        // reading from this memory will SEGFAULT
        // unless we are in read or readwrite protection mode
        //
        // INVARIANTS:
        //   - z was allocated with sodium_malloc
        //   - we must not dereference beyond the end of allocated memory
        unsafe {
            &std::slice::from_raw_parts(self.z as *const u8, self.s)[..self.s]
        }
    }

    /// as a slice mut
    pub(crate) fn as_slice_mut(&mut self) -> &mut [u8] {
        if *self.p.borrow() != ProtectState::ReadWrite {
            panic!("DerefMut, but state is not ReadWrite");
        }

        // reading from this memory will SEGFAULT
        // unless we are in readwrite protection mode
        //
        // INVARIANTS:
        //   - z was allocated with sodium_malloc
        //   - we must not dereference beyond the end of allocated memory
        unsafe {
            &mut std::slice::from_raw_parts_mut(self.z as *mut u8, self.s)
                [..self.s]
        }
    }

    /// as array
    pub(crate) fn as_sized<const N: usize>(&self) -> &[u8; N] {
        assert_eq!(self.s, N);
        unsafe { &*(self.as_slice().as_ptr() as *const [_; N]) }
    }

    /// as array mut
    pub(crate) fn as_sized_mut<const N: usize>(&mut self) -> &mut [u8; N] {
        assert_eq!(self.s, N);
        unsafe { &mut *(self.as_slice_mut().as_mut_ptr() as *mut [_; N]) }
    }
}

impl std::fmt::Debug for S3Buf {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self.p.borrow() {
            ProtectState::NoAccess => {
                write!(f, "Buffer {{ {:?} }}", "<NO_ACCESS>")
            }
            _ => write!(f, "Buffer {{ {:?} }}", *self),
        }
    }
}
