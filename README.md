# sodoken

<!-- cargo-rdme start -->

lib SOdium + haDOKEN = SODOKEN!

Thin wrapper around libsodium-sys-stable.

[![Project](https://img.shields.io/badge/project-holochain-blue.svg?style=flat-square)](http://holochain.org/)
[![Forum](https://img.shields.io/badge/chat-forum%2eholochain%2enet-blue.svg?style=flat-square)](https://forum.holochain.org)
[![Chat](https://img.shields.io/badge/chat-chat%2eholochain%2enet-blue.svg?style=flat-square)](https://chat.holochain.org)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

```rust
use sodoken::*;

let mut pub_key = [0; sign::PUBLICKEYBYTES];
let mut sec_key = SizedLockedArray::new().unwrap();

sign::keypair(&mut pub_key, &mut sec_key.lock()).unwrap();

let mut sig = [0; sign::SIGNATUREBYTES];

sign::sign_detached(&mut sig, b"hello", &sec_key.lock()).unwrap();
assert!(sign::verify_detached(&sig, b"hello", &pub_key));
assert!(!sign::verify_detached(&sig, b"world", &pub_key));
```

<!-- cargo-rdme end -->
