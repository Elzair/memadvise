`memadvise` is a Rust crate that can provide the operating system with hints about memory access patterns. For example, if the user calls `memadvise::advise()` with `Advice::Sequential`, the kernel may start bringing memory pages into RAM (if they were on disk) starting at the beginning of the block of memory passed.

# Example

```rust
extern crate memadvise;
extern crate page_size;

fn main() {
    // Allocate block of memory in a system specific manner.

    // Get portion of memory block (must be aligned to system page size).
    let address: *mut () = ...
    let length = 320000;
    
    // Tell the OS to start loading this portion into RAM starting at the beginning.
    memadvise::advise(address, length, Advice::Sequential).unwrap();
    
    // Do something with this portion of memory
    
    // Tell the OS we do not need this portion right now.
    // That way, the OS can safely swap it out to disk.
    memadvise::advise(address, length, Advice::DontNeed).unwrap();
    
    // Do some other stuff.
    
    // Be sure to free block of memory (system specific) at the end.
}

```

# Advice

`memadvise` features five different 'hints' used to tell the system how a program will use a certain range of memory.

* `Normal` - no special usage

* `Random` - will use range but in no particular order; OS should not read ahead much

* `WillNeed` - will use range; OS should read ahead more than `Random`

* `Sequential` - will use range in order; OS should read ahead more than `WillNeed`

* `DontNeed` - will not use range right now; OS can swap it to disk


