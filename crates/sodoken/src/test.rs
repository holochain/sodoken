use crate::*;

#[test]
fn test_buffer_extend() {
    let buf = BufWrite::new_unbound_no_lock();
    let ext = buf.to_extend();
    ext.extend_lock().extend_mut_from_slice(b"hello ").unwrap();
    ext.extend_lock()
        .extend_mut(6)
        .unwrap()
        .copy_from_slice(b"world!");
    let s = String::from_utf8_lossy(&*buf.read_lock()).to_string();
    assert_eq!("hello world!", &s);
}
