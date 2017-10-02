#![no_std]

//! This crate provides the operating system with hints about memory access
//! patterns. For example, if the user calls memadvise::advise() with
//! Advice::Sequential, the kernel may start bringing memory pages into
//! RAM (if they were on disk) starting at the beginning of the block of
//! memory passed.
//!
//! # Example
//!
//! This example shows the basic usage of the crate.
//!
//! ```rust,ignore
//! extern crate memadvise;
//! extern crate page_size;
//! 
//! // Allocate block of memory in a system specific manner.
//! 
//! // Get portion of memory block (must be aligned to system page size).
//! let address: *mut () = ... 
//! let length = 320000;
//! 
//! // Tell the OS to start loading this portion into RAM starting at the beginning.
//! memadvise::advise(address, length, Advice::Sequential).unwrap();
//! 
//! // Do something with this portion of memory.
//! 
//! // Tell the OS we do not need this portion right now.
//! // That way, the OS can safely swap it out to disk.
//! memadvise::advise(address, length, Advice::DontNeed).unwrap();
//!
//! // Do some other stuff.
//!
//! // Be sure to free block of memory (system specific) at the end.
//! ```

// `const_fn` is needed for `spin::Once`.
#![cfg_attr(feature = "no_std", feature(const_fn))]
#![cfg_attr(all(feature = "no_std", not(windows)), allow(unused_extern_crates))]

extern crate page_size;

#[cfg(not(feature = "no_std"))]
extern crate std;

#[cfg(unix)]
extern crate libc;

#[cfg(windows)]
extern crate winapi;
#[cfg(windows)]
extern crate kernel32;
#[cfg(feature = "no_std")]
extern crate spin;

pub enum Advice {
    /// No special usage
    Normal,
    /// Will access memory block in order from low address to high address; OS should aggressively read ahead 
    Sequential,
    /// Will access random chunks from memory block; OS may not have to read ahead
    Random,
    /// Will need to access this memory block soon; OS should read ahead
    WillNeed,
    /// Will NOT need to access this memory block soon
    DontNeed,
}

/// This function gives the system advice about a certain block of memory.
///
/// # Arguments
///
/// * address - a raw pointer to a memory address that must be a multiple of the system's page size
///
/// * length - size of memory block in bytes (must be nonzero)
///
/// * advice - hint to pass to the operating system
pub fn advise(address: *mut (), length: usize, advice: Advice)
                     -> Result<(), MemAdviseError> {
    advise_helper(address, length, advice)
}

/// The possible errors returned by `advise()`
pub enum MemAdviseError {
    /// Passed null pointer in `address` field
    NullAddress,
    /// Invalid value for `length`
    InvalidLength,
    /// `address` is not properly aligned
    UnalignedAddress,
    /// Memory block is invalid for some other reason
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

    #[cfg(target_os = "android")]
    use libc::{c_void, madvise, MADV_DONTNEED, MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED};
    #[cfg(not(target_os = "android"))]
    use libc::{c_void, posix_madvise as madvise, POSIX_MADV_DONTNEED as MADV_DONTNEED, POSIX_MADV_NORMAL as MADV_NORMAL, POSIX_MADV_RANDOM as MADV_RANDOM, POSIX_MADV_SEQUENTIAL as MADV_SEQUENTIAL, POSIX_MADV_WILLNEED as MADV_WILLNEED};

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
            Advice::DontNeed => MADV_DONTNEED,
            Advice::Normal => MADV_NORMAL,
            Advice::Random => MADV_RANDOM,
            Advice::Sequential => MADV_SEQUENTIAL,
            Advice::WillNeed => MADV_WILLNEED,
        };

        let res = unsafe {
            madvise(address as *mut c_void,
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

    #[cfg(feature = "no_std")]
    use core::mem;
    #[cfg(not(feature = "no_std"))]
    use std::mem;

    use kernel32::{GetCurrentProcess, PrefetchVirtualMemory, VerifyVersionInfoA, VerSetConditionMask};

    use winapi::basetsd::{SIZE_T, ULONG_PTR};
    use winapi::memoryapi::{PWIN32_MEMORY_RANGE_ENTRY, WIN32_MEMORY_RANGE_ENTRY};
    use winapi::minwindef::{BYTE, DWORD, ULONG};
    use winapi::winnt::{LPOSVERSIONINFOEXA, OSVERSIONINFOEXA, PVOID, ULONGLONG};

    #[cfg(feature = "no_std")]
    use spin::Once;
    #[cfg(not(feature = "no_std"))]
    use std::sync::{Once, ONCE_INIT};

    use page_size;
    
    use super::{Advice, MemAdviseError};

    const VER_MAJORVERSION: DWORD = 0x2;
    const VER_MINORVERSION: DWORD = 0x1;
    const VER_GREATER_EQUAL: BYTE = 0x3;

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

        // // Do nothing if we are running on Windows 7.
        // if !is_prefetch_supported() {
        //     return Ok(())
        // }

        let res = unsafe {
            PrefetchVirtualMemory(
                GetCurrentProcess(),
                1 as ULONG_PTR,
                &mut memrange as PWIN32_MEMORY_RANGE_ENTRY,
                0 as ULONG
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

    // Only Windows8+ supports `kernel32::PrefetchVirtualMemory()`.
    #[cfg(all(windows, feature = "no_std"))]
    #[inline]
    fn is_prefetch_supported() -> bool {
        static INIT: Once<bool> = Once::new();
        
        *INIT.call_once(supported_helper)
    }

    #[cfg(all(windows, not(feature = "no_std")))]
    #[inline]
    fn is_prefetch_supported() -> bool {
        static INIT: Once = ONCE_INIT;
        static mut SUPPORTED: bool = false;

        unsafe {
            INIT.call_once(|| SUPPORTED = supported_helper());
            SUPPORTED
        }
    }

    #[inline]
    fn supported_helper() -> bool {
        // Build type mask.
        let type_mask = VER_MAJORVERSION | VER_MINORVERSION;
        
        // Build condition mask.
        let cond_mask = unsafe {
            VerSetConditionMask(
                0 as ULONGLONG,
                type_mask,
                VER_GREATER_EQUAL
            )
        };
        
        // Initialize version info.
        let mut info: OSVERSIONINFOEXA = unsafe { mem::zeroed() };
        info.dwMajorVersion = 6 as DWORD;
        info.dwMinorVersion = 2 as DWORD;

        // Test version
        let res = unsafe {
            VerifyVersionInfoA(
                &mut info as LPOSVERSIONINFOEXA,
                type_mask,
                cond_mask
            )
        };

        res != 0
    }

    #[cfg(test)]
    mod tests {
        use kernel32::{VirtualAlloc, VirtualFree};

        use winapi::basetsd::SIZE_T;
        use winapi::minwindef::{BOOL, DWORD, LPVOID};
        use winapi::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

        use super::*;

        #[test]
        fn test_windows_memadvise() {
            let length = page_size::get() as SIZE_T;

            let address = unsafe {
                VirtualAlloc(
                    ptr::null_mut() as LPVOID,
                    length,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                )
            };

            assert_ne!(address, ptr::null_mut() as LPVOID);

            let addr = address as *mut ();
            let len = length as usize;
            
            match advise(addr, len, Advice::WillNeed) {
                Ok(_) => {},
                _ => { assert!(false); },
            }
                        
            match advise(addr, len, Advice::DontNeed) {
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
        fn test_windows_memadvise_unaligned_address() {
            let mut test = page_size::get() + 1;
            let address = &mut test as *mut usize as *mut ();

            match advise(address, 64, Advice::Normal) {
                Err(MemAdviseError::UnalignedAddress) => {},
                _ => { assert!(false); },
            }
        }

        #[test]
        fn test_windows_memadvise_invalid_range() {
            let address = page_size::get() as *mut usize as *mut ();

            match advise(address, 64, Advice::Normal) {
                Err(MemAdviseError::InvalidRange) => {},
                Ok(_) => { println!("Valid Range!"); },
                Err(MemAdviseError::UnalignedAddress) => {
                    println!("Unaligned Address!");
                },
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

        let length = page_size::get() as SIZE_T;

        let address = unsafe {
            VirtualAlloc(
                ptr::null_mut() as LPVOID,
                length as SIZE_T,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
        };

        assert_ne!(address, ptr::null_mut() as LPVOID);

        let addr = address as *mut ();
        let len = length as usize;
        
        match advise(addr, len, Advice::WillNeed) {
            Ok(_) => {},
            _ => { assert!(false); },
        }
        
        match advise(addr, len, Advice::DontNeed) {
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
