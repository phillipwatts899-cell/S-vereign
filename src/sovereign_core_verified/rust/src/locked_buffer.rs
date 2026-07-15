use libc::{c_void, mlock, munlock};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr;

#[derive(Debug)]
pub enum LockedBufferError {
    InvalidLayout,
    AllocationFailed,
    MlockFailed(std::io::Error),
}

/// mlock()-protected buffer built on raw allocator calls (not Vec), so that
/// an oversized or resource-exhausted allocation returns a catchable Result
/// instead of aborting the process. Vec's default allocation path is
/// infallible -- allocation failure there calls handle_alloc_error and
/// aborts unconditionally, which is unacceptable for a size that could
/// ever be influenced, even indirectly, by untrusted input.
/// Implemented by anything that can serve as a decrypt/write target via a
/// raw locked-memory pointer -- lets transport::open_sealed accept either
/// a plain LockedBuffer or a PadStore (in defer_fill mode) as its output,
/// without PadStore needing to expose its internal LockedBuffer field
/// directly. Rust equivalent of the duck-typing (.addr/.size) the Python
/// port relies on for the same zero-intermediate-copy purpose.
pub trait RawWriteTarget {
    fn as_mut_ptr_raw(&mut self) -> *mut u8;
    fn len(&self) -> usize;
}

impl RawWriteTarget for LockedBuffer {
    fn as_mut_ptr_raw(&mut self) -> *mut u8 {
        self.ptr
    }
    fn len(&self) -> usize {
        self.len
    }
}

pub struct LockedBuffer {
    ptr: *mut u8,
    len: usize,
    layout: Layout,
    locked: bool,
}

impl LockedBuffer {
    pub fn new(size: usize) -> Result<Self, LockedBufferError> {
        if size == 0 {
            return Err(LockedBufferError::InvalidLayout);
        }
        let layout = Layout::array::<u8>(size).map_err(|_| LockedBufferError::InvalidLayout)?;
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(LockedBufferError::AllocationFailed);
        }
        let rc = unsafe { mlock(ptr as *mut c_void, size) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { dealloc(ptr, layout) }; // don't leak the allocation on mlock failure
            return Err(LockedBufferError::MlockFailed(err));
        }
        Ok(LockedBuffer { ptr, len: size, layout, locked: true })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Raw mutable pointer to the locked buffer's start. Exposed for
    /// external population use cases (e.g. a decryption routine writing
    /// pad material directly in). Caller must not write beyond len() bytes.
    pub fn as_mut_ptr_raw(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), &'static str> {
        if offset + data.len() > self.len {
            return Err("write exceeds buffer bounds");
        }
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn clear(&mut self) {
        if !self.locked {
            return;
        }
        unsafe {
            for i in 0..self.len {
                ptr::write_volatile(self.ptr.add(i), 0u8);
            }
            munlock(self.ptr as *mut c_void, self.len);
        }
        self.locked = false;
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.clear();
        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_succeeds() {
        LockedBuffer::new(64).expect("mlock should succeed in this sandbox");
    }

    #[test]
    fn write_at_correctness() {
        let mut buf = LockedBuffer::new(64).unwrap();
        let pattern: Vec<u8> = (0..32).collect();
        buf.write_at(0, &pattern).unwrap();
        assert_eq!(&buf.as_slice()[0..32], &pattern[..]);
    }

    #[test]
    fn out_of_bounds_write_rejected() {
        let mut buf = LockedBuffer::new(64).unwrap();
        let big = vec![0u8; 100];
        assert!(buf.write_at(0, &big).is_err());
    }

    #[test]
    fn explicit_clear_zeroes_buffer() {
        let mut buf = LockedBuffer::new(64).unwrap();
        buf.write_at(0, &[0xFFu8; 64]).unwrap();
        buf.clear();
        assert!(buf.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn clear_is_idempotent() {
        let mut buf = LockedBuffer::new(32).unwrap();
        buf.clear();
        buf.clear(); // must not panic
    }

    #[test]
    fn scoped_drop_does_not_panic() {
        let mut scoped_buf = LockedBuffer::new(32).expect("mlock should succeed");
        scoped_buf.write_at(0, &[0xFFu8; 32]).unwrap();
        // dropped at end of scope
    }

    #[test]
    fn oversized_allocation_returns_err_not_abort() {
        // 4 GiB -- must return a controlled Err, not abort the test process.
        match LockedBuffer::new(4 * 1024 * 1024 * 1024) {
            Err(_) => {} // expected
            Ok(_) => panic!("4 GiB allocation unexpectedly succeeded -- cannot assert failure here, but did not abort either way"),
        }
    }
}
