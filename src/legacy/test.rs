use crate::legacy::*;
use std::sync::Arc;

#[test]
fn test_buffer_extend() {
    let ext = BufExtend::new_no_lock(0);
    ext.extend_lock().extend_mut_from_slice(b"hello ").unwrap();
    ext.extend_lock()
        .extend_mut(6)
        .unwrap()
        .copy_from_slice(b"world!");
    let s = String::from_utf8_lossy(&*ext.read_lock()).to_string();
    assert_eq!("hello world!", &s);
}

#[test]
fn test_try_unwrap() {
    fn ok<B: Into<BufRead>>(b: B) -> SodokenResult<()> {
        match b.into().try_unwrap() {
            Ok(b) => {
                assert_eq!(b"test", &*b);
                Ok(())
            }
            Err(_) => Err("unwrap fail".into()),
        }
    }

    ok(BufRead::from(<Box<[u8]>>::from(&b"test"[..]))).unwrap();
    ok(BufRead::from(<Vec<u8>>::from(&b"test"[..]))).unwrap();
    ok(BufWrite::from(<Vec<u8>>::from(&b"test"[..]))).unwrap();
    ok(BufWriteSized::from(*b"test")).unwrap();

    let locked = BufWrite::new_mem_locked(4).unwrap();
    locked.write_lock().copy_from_slice(b"test");
    ok(locked).unwrap_err();
}

#[test]
fn test_try_unwrap_sized() {
    fn ok<B: Into<BufReadSized<4>>>(b: B) -> SodokenResult<()> {
        match b.into().try_unwrap_sized() {
            Ok(b) => {
                assert_eq!(b"test", &b);
                Ok(())
            }
            Err(_) => Err("unwrap fail".into()),
        }
    }

    ok(<BufReadSized<4>>::from(<Arc<[u8; 4]>>::from(*b"test"))).unwrap();
    ok(<BufReadSized<4>>::from(*b"test")).unwrap();
    ok(<BufWriteSized<4>>::from(*b"test")).unwrap();

    let locked = <BufWriteSized<4>>::new_mem_locked().unwrap();
    locked.write_lock().copy_from_slice(b"test");
    ok(locked).unwrap_err();
}
