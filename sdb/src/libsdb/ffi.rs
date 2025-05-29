use nix::libc;

use std::os::raw::{c_char, c_int};
use libc::size_t;

#[link(name = "stdc++")]    // Only support Linux os
unsafe extern "C" {
    fn __cxa_demangle(
        mangled: *const c_char,
        out_buf: *mut c_char,
        out_len: *mut size_t,
        status:  *mut c_int,
    ) -> *mut c_char;
}

use std::ffi::{CStr, CString};
use std::ptr;

pub fn demangle(name: &str) -> Option<String> {
    let c_name = CString::new(name).ok()?;
    let mut status = 0;
    unsafe {
        let demangled_ptr = __cxa_demangle(c_name.as_ptr(), ptr::null_mut(), ptr::null_mut(), &mut status);
        if status == 0 && !demangled_ptr.is_null() {
            let result = CStr::from_ptr(demangled_ptr).to_string_lossy().into_owned();
            libc::free(demangled_ptr as *mut libc::c_void);
            Some(result)
        } else {
            None
        }
    }
}

#[test]
fn test_demangle() {
    let mangled = "_ZSt4cout"; // e.g., std::cout
    assert_eq!("std::cout", demangle(mangled).unwrap());
}