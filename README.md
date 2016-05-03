# rust-multihash

[multihash](https://github.com/jbenet/multihash) implementation in Rust.

# Usage

```rust
extern crate rust_multihash;

use rust_multihash::{multihash, Multihash, HashType};

fn main() {
    let hash = "QmR6XorNYAywK4q1dRiRN1gmvfLcx3ccBv68iGtAqon9tt";
    let mh1 = Multihash::from_base58_str(hash).unwrap();

    // `multihash` is a convenience function that hashes a slice
    // of bytes and returns it as a Multihash
    let data = b"Hello, universe!";
    let mh2 = multihash(data, HashType::SHA2_256);
}
```
