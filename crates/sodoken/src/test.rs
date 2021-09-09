use crate::*;

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
