#![no_std]

//! This crate advises the system about the usage patterns of memory.

extern crate page_size;


#[cfg(not(feature = "no_std"))]
extern crate std;

#[cfg(unix)]
extern crate libc;

pub enum Advice {
    Normal,
    Sequential,
    Random,
    WillNeed,
    DontNeed,
}

/// This function gives the system advice about a certain block of memory.
pub fn advise(address: *mut (), length: usize, advice: Advice)
                     -> Result<(), MemAdviseError> {
    advise_helper(address, length, advice)
}

/// The possible errors returned by `advise()`
pub enum MemAdviseError {
    NullAddress,
    InvalidLength,
    UnalignedAddress,
    InvalidRange,
}

// Unix Section

#[cfg(unix)]
#[inline]
pub fn advise_helper(address: *mut (), length: usize, advice: Advice)
                            -> Result<(), MemAdviseError> {
    unix::advise(address, length, advice)
}

#[cfg(unix)]
mod unix {
    #[cfg(feature = "no_std")]
    use core::ptr;
    #[cfg(not(feature = "no_std"))]
    use std::ptr;

    use libc::{c_void, posix_madvise, POSIX_MADV_DONTNEED, POSIX_MADV_NORMAL, POSIX_MADV_RANDOM, POSIX_MADV_SEQUENTIAL, POSIX_MADV_WILLNEED};

    use page_size;
    
    use super::{Advice, MemAdviseError};
    
    #[inline]
    pub fn advise(address: *mut (),
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
            Advice::DontNeed => POSIX_MADV_DONTNEED,
            Advice::Normal => POSIX_MADV_NORMAL,
            Advice::Random => POSIX_MADV_RANDOM,
            Advice::Sequential => POSIX_MADV_SEQUENTIAL,
            Advice::WillNeed => POSIX_MADV_WILLNEED,
        };

        let res = unsafe {
            posix_madvise(address as *mut c_void,
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
        use libc::{MAP_ANON, MAP_PRIVATE, PROT_READ, mmap, munmap};
        
        use super::*;

        // Anonymous maps are not part of the POSIX standard, but they are widely available.
        // We use `libc::MAP_ANON` since NetBSD does not support `libc::MAP_ANONYMOUS`.
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd", target_os = "android"))]
        #[test]
        fn test_unix_memadvise() {
            let length = 2 * page_size::get();

            let address = unsafe {
                mmap(ptr::null_mut(),
                     length,
                     PROT_READ,
                     MAP_PRIVATE | MAP_ANON,
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
                munmap(address, length)
            };
            
            assert_eq!(res, 0);
        }

        #[test]
        fn test_unix_memadvise_null_address() {
            match advise(ptr::null_mut(), 0, Advice::Normal) {
                Err(MemAdviseError::NullAddress) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_unix_memadvise_zero_length() {
            let mut test: usize = 3;
            let address = &mut test as *mut usize as *mut ();

            match advise(address, 0, Advice::Normal) {
                Err(MemAdviseError::InvalidLength) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_unix_memadvise_unaligned_address() {
            let mut test = page_size::get() + 1;
            let address = &mut test as *mut usize as *mut ();

            match advise(address, 64, Advice::Normal) {
                Err(MemAdviseError::UnalignedAddress) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_unix_memadvise_invalid_range() {
            // We cannot use a value of 0 for the address, since that would
            // be caught by the null pointer check. The second page of memory
            // in the address space is almost certainly invalid.
            let address = page_size::get() as *mut usize as *mut ();

            match advise(address, 64, Advice::Normal) {
                Err(MemAdviseError::InvalidRange) => {},
                _ => { assert!(false); },
            }
        }
    }
}

// Windows Section
#[cfg(windows)]
extern crate winapi;
#[cfg(windows)]
extern crate kernel32;

#[cfg(windows)]
#[inline]
pub fn advise_helper(address: *mut (), length: usize, advice: Advice)
                     -> Result<(), MemAdviseError> {
    windows::advise(address, length, advice)
}

#[cfg(windows)]
mod windows {
    #[cfg(feature = "no_std")]
    use core::ptr;
    #[cfg(not(feature = "no_std"))]
    use std::ptr;

    use super::{Advice, MemAdviseError};

    use kernel32::{GetCurrentProcess, PrefetchVirtualMemory};

    use winapi::basetsd::{SIZE_T, ULONG_PTR};
    use winapi::memoryapi::{PWIN32_MEMORY_RANGE_ENTRY, WIN32_MEMORY_RANGE_ENTRY};
    use winapi::minwindef::BOOL;
    use winapi::winnt::PVOID;
    
    #[inline]
    pub fn advise(address: *mut (),
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

        // Windows only really supports `Advice::WillNeed`.
        // `Advice::{Random, Sequential, WillNeed}` all tell the system to
        // prefetch memory. `Advice::{DontNeed, Normal}` do not do anything.
        match advice {
            Advice::Normal | Advice::DontNeed => {
                return Ok(());
            },
            _ => {},
        }

        let mut memrange = WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: address as PVOID,
            NumberOfBytes: length as SIZE_T,
        };

        let res = unsafe {
            PrefetchVirtualMemory(
                GetCurrentProcess(),
                1 as ULONG_PTR,
                &mut memrange as PWIN32_MEMORY_RANGE_ENTRY
            )
        };

        // Check that function completed successfully.
        if res == 0 {
            Err(MemAdviseError::InvalidRange)
        }
        else {
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use kernel32::{VirtualAlloc, VirtualFree};

        use winapi::basetsd::SIZE_T;
        use winapi::minwindef::{BOOL, DWORD, LPVOID};
        use winapi::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

        #[test]
        fn test_windows_memadvise() {
            let address = unsafe {
                VirtualAlloc(
                    ptr::null_mut() as LPVOID,
                    length,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                )
            };

            assert_ne!(address, ptr::null_mut() as LPVOID);

            let length = page_size::get() as SIZE_T;
            
            match advise_windows(address, length, Advice::WillNeed) {
                Ok(_) => {},
                _ => { assert!(false); },
            }
                        
            match advise_windows(address, length, Advice::DontNeed) {
                Ok(_) => {},
                _ => { assert!(false); },
            }

            let res = unsafe { VirtualFree(address, 0, MEM_RELEASE) };

            assert_ne!(res, 0 as BOOL);
        }

        #[test]
        fn test_windows_memadvise_null_address() {
            match advise(ptr::null_mut(), 0, Advice::Normal) {
                Err(MemAdviseError::NullAddress) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_windows_memadvise_zero_length() {
            let mut test: usize = 3;
            let address = &mut test as *mut usize as *mut ();

            match advise(address, 0, Advice::Normal) {
                Err(MemAdviseError::InvalidLength) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_windows_memadvise_invalid_range() {
            let address = page_size::get() as *mut usize as *mut ();

            match advise(address, 64, Advice::Normal) {
                Err(MemAdviseError::InvalidRange) => {},
                _ => { assert!(false); },
            }
        }
    }
}


// Stub Section

#[cfg(not(any(unix, windows)))]
#[inline]
pub fn advise_helper(address: *mut (), length: usize, advice: Advice)
                            -> Result<(), MemAdviseError> {
    stub::advise(address, length, advice)
}

#[cfg(not(any(unix, windows)))]
mod stub {
    #[cfg(feature = "no_std")]
    use core::ptr;
    #[cfg(not(feature = "no_std"))]
    use std::ptr;

    use super::{Advice, MemAdviseError};
    
    #[inline]
    pub fn advise(address: *mut (),
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

        Ok(())
    }
    
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_stub_memadvise() {
            let test: usize = 3;
            let address = &test as *mut usize as *mut ();

            match advise(address, 64, Advice::Normal) {
                Ok(_) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_windows_memadvise_null_address() {
            match advise(ptr::null_mut(), 0, Advice::Normal) {
                Err(MemAdviseError::NullAddress) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_windows_memadvise_zero_length() {
            let mut test: usize = 3;
            let address = &mut test as *mut usize as *mut ();

            match advise(address, 0, Advice::Normal) {
                Err(MemAdviseError::InvalidLength) => {},
                _ => { assert!(false); },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "no_std")]
    use core::ptr;
    #[cfg(not(feature = "no_std"))]
    use std::ptr;

    use super::*;
    
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd", target_os = "android"))]
    #[test]
    fn test_memadvise_most_unices() {
        use libc::{PROT_READ, MAP_PRIVATE, MAP_ANON, _SC_PAGESIZE, mmap, munmap, size_t, sysconf};
        
        let page_size = unsafe {
            sysconf(_SC_PAGESIZE) as size_t
        };
        
        let length = 2 * page_size;

        let address = unsafe {
            mmap(ptr::null_mut(),
                 length,
                 PROT_READ,
                 MAP_PRIVATE | MAP_ANON,
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
            munmap(address, length)
        };
        
        assert_eq!(res, 0);
    }

    #[cfg(windows)]
    #[test]
    fn test_memadvise_windows() {
        use kernel32::{VirtualAlloc, VirtualFree};

        use winapi::basetsd::SIZE_T;
        use winapi::minwindef::{BOOL, DWORD, LPVOID};
        use winapi::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

        let address = unsafe {
            VirtualAlloc(
                ptr::null_mut() as LPVOID,
                length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
        };

        assert_ne!(address, ptr::null_mut() as LPVOID);

        let length = page_size::get() as SIZE_T;
        
        match advise(address, length, Advice::WillNeed) {
            Ok(_) => {},
            _ => { assert!(false); },
        }
        
        match advise(address, length, Advice::DontNeed) {
            Ok(_) => {},
            _ => { assert!(false); },
        }

        let res = unsafe { VirtualFree(address, 0, MEM_RELEASE) };

        assert_ne!(res, 0 as BOOL);
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn test_memadvise_stub() {
        advise(ptr::null_mut(), 0, Advice::Normal);
    }
}
