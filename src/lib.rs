#![no_std]

extern crate page_size;

#[cfg(feature = "no-std")]
use core::ptr;

#[cfg(not(feature = "no-std"))]
extern crate std;
#[cfg(not(feature = "no-std"))]
use std::ptr;

extern crate libc;

pub enum Advice {
    Normal,
    Sequential,
    Random,
    WillNeed,
    DontNeed,
}

pub fn advise(address: *mut (), length: usize, advice: Advice)
                     -> Result<(), MemAdviseError> {
    advise_helper(address, length, advice)
}

pub enum MemAdviseError {
    NullAddress,
    InvalidLength,
    UnalignedAddress,
    InvalidRange,
}

// Unix Section

#[cfg(any(unix))]
#[inline]
pub fn advise_helper(address: *mut (), length: usize, advice: Advice)
                            -> Result<(), MemAdviseError> {
    unix::advise_unix(address, length, advice)
}

#[cfg(any(unix))]
mod unix {
    use super::*;
    
    #[inline]
    pub fn advise_unix(address: *mut (),
                       length: usize,
                       advice: Advice)
                       -> Result<(), MemAdviseError>
    {
        // Check for null pointer.
        if address == ptr::null_mut() {
            return Err(MemAdviseError::NullAddress);
        }

        // Check for invalid length.
        if length == 0 {
            return Err(MemAdviseError::InvalidLength);
        }

        // Ensure `address` is a multiple of the system page size.
        // Assume the page size is a power of 2.
        let page_size = page_size::get();
        let ptr_usize = address as usize;

        if ptr_usize & !(page_size - 1) != ptr_usize {
            return Err(MemAdviseError::UnalignedAddress);
        }

        // Get Advice value
        let advice_internal = match advice {
            Advice::DontNeed => libc::POSIX_MADV_DONTNEED,
            Advice::Normal => libc::POSIX_MADV_NORMAL,
            Advice::Random => libc::POSIX_MADV_RANDOM,
            Advice::Sequential => libc::POSIX_MADV_SEQUENTIAL,
            Advice::WillNeed => libc::POSIX_MADV_WILLNEED,
        };

        let res = unsafe {
            libc::posix_madvise(address as *mut libc::c_void,
                                length,
                                advice_internal)
        };

        if res == 0 {
            Ok(())
        }
        // Assume that the system call failed because of an invalid address range.
        // We *SHOULD* have handled any other invalid inputs.
        else {
            Err(MemAdviseError::InvalidRange)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // Anonymous maps are not part of the supported standard, but they are widely available.
        // We use `libc::MAP_ANON` since NetBSD does not support `libc::MAP_ANONYMOUS`.
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd", target_os = "android"))]
        #[test]
        fn test_unix_memadvise() {
            let page_size = unsafe {
                libc::sysconf(libc::_SC_PAGESIZE) as libc::size_t
            };
            
            let length = 2 * page_size;

            let address = unsafe {
                libc::mmap(ptr::null_mut(),
                           length,
                           libc::PROT_READ,
                           libc::MAP_PRIVATE | libc::MAP_ANON,
                           -1,
                           0)
            };
            
            assert_ne!(address, ptr::null_mut());
            
            match advise_unix(address as *mut (),
                              length as usize,
                              Advice::WillNeed) {
                Ok(_) => {},
                _ => { assert!(false); },
            }
            
            match advise_unix(address as *mut (),
                              length as usize,
                              Advice::DontNeed) {
                Ok(_) => {},
                _ => { assert!(false); },
            }

            let res = unsafe {
                libc::munmap(address, length)
            };
            
            assert_eq!(res, 0);
        }

        #[test]
        fn test_unix_memadvise_null_address() {
            match advise_unix(ptr::null_mut(), 0, Advice::Normal) {
                Err(MemAdviseError::NullAddress) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_unix_memadvise_zero_length() {
            let mut test: usize = 3;
            let p = &mut test as *mut usize as *mut ();

            match advise_unix(p, 0, Advice::Normal) {
                Err(MemAdviseError::InvalidLength) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_unix_memadvise_unaligned_address() {
            let page_size = unsafe {
                libc::sysconf(libc::_SC_PAGESIZE) as usize
            };

            let mut test = page_size + 1;
            let p = &mut test as *mut usize as *mut ();

            match advise_unix(p, 64, Advice::Normal) {
                Err(MemAdviseError::UnalignedAddress) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_unix_memadvise_invalid_range() {
            let page_size = unsafe {
                libc::sysconf(libc::_SC_PAGESIZE) as usize
            };

            let p = page_size as *mut usize as *mut ();

            match advise_unix(p, 64, Advice::Normal) {
                Err(MemAdviseError::InvalidRange) => {},
                _ => { assert!(false); },
            }
        }
    }
}

// Stub Section

#[cfg(not(any(unix)))]
#[inline]
pub fn advise_helper(address: *mut (), length: usize, advice: Advice)
                            -> Result<(), MemAdviseError> {
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd", target_os = "android"))]
    #[test]
    fn test_memadvise() {
        let page_size = unsafe {
            libc::sysconf(libc::_SC_PAGESIZE) as libc::size_t
        };
        
        let length = 2 * page_size;

        let address = unsafe {
            libc::mmap(ptr::null_mut(),
                       length,
                       libc::PROT_READ,
                       libc::MAP_PRIVATE | libc::MAP_ANON,
                       -1,
                       0)
        };
        
        assert_ne!(address, ptr::null_mut());
        
        match advise(address as *mut (),
                          length as usize,
                          Advice::WillNeed) {
            Ok(_) => {},
            _ => { assert!(false); },
        }
        
        match advise(address as *mut (),
                          length as usize,
                          Advice::DontNeed) {
            Ok(_) => {},
            _ => { assert!(false); },
        }

        let res = unsafe {
            libc::munmap(address, length)
        };
        
        assert_eq!(res, 0);
    }

    #[cfg(not(any(unix)))]
    fn test_memadvise_stub() {
        advise(ptr::null_mut(), 0, Advice::Normal);
    }
}
