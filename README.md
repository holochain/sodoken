<a href="https://github.com/holochain/sodoken/blob/master/LICENSE-APACHE">![Crates.io](https://img.shields.io/crates/l/sodoken)</a>
<a href="https://crates.io/crates/sodoken">![Crates.io](https://img.shields.io/crates/v/sodoken)</a>

# sodoken

lib SOdium + haDOKEN = SODOKEN!

libsodium wrapper providing tokio safe memory secure api access.

This crate-level documentation mainly describes how to work with the
sodoken buffer types. Please see the individual module-level documentation
for usage examples and descriptions of individual crypto functions.

##### Sodoken Buffers

Sodoken buffers provide implementors with the ability to optionally
use secured memory (mlock + mprotect) to mitigate some secret exposure
channels like disk swapping. Buffers created with `new_mem_locked`
are secured, buffers created with `new_no_lock` are not.

Please note that on most systems, locked memory is a finite resource,
so you should use it for private keys, but not everything.

All buffers are shallow-cloned by default, so `buf.clone()` or any of the
`buf.to_*()` apis will give you a reference to the same buffer. You
can deep clone the buffers with the `buf.deep_clone_mem_locked()` or
`buf.deep_clone_no_lock()` apis.

In general, the steps for working with sodoken apis are:
- create a writable buffer
- shallow clone that buffer into an api
- translate that buffer into a read-only version for future use

##### Buffer Example

```rust
// create a writable buffer
let salt: sodoken::BufWriteSized<{ sodoken::hash::argon2id::SALTBYTES }> =
    sodoken::BufWriteSized::new_no_lock();

// shallow clone that buffer into an api
sodoken::random::bytes_buf(salt.clone()).await.unwrap();

// translate that buffer into a read-only version for future use
let salt = salt.to_read_sized();
```
