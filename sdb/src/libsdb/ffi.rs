use nix::libc;

use libc::size_t;
use std::os::raw::{c_char, c_int};

#[link(name = "stdc++")] // Only support Linux os
unsafe extern "C" {
    fn __cxa_demangle(
        mangled: *const c_char,
        out_buf: *mut c_char,
        out_len: *mut size_t,
        status: *mut c_int,
    ) -> *mut c_char;
}

use std::ffi::{CStr, CString};
use std::ptr;

pub fn demangle(name: &str) -> Option<String> {
    let c_name = CString::new(name).ok()?;
    let mut status = 0;
    unsafe {
        let demangled_ptr = __cxa_demangle(
            c_name.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut status,
        );
        if status == 0 && !demangled_ptr.is_null() {
            let result = CStr::from_ptr(demangled_ptr).to_string_lossy().into_owned();
            libc::free(demangled_ptr as *mut libc::c_void);
            Some(result)
        } else {
            None
        }
    }
}

unsafe extern "C" {
    // GNU‐only; not present on musl or non-Linux targets
    fn sigabbrev_np(signum: c_int) -> *const c_char;
}

#[cfg(target_env = "gnu")] // build only when the host libc is glibc
pub fn sig_abbrev(signum: i32) -> &'static str {
    unsafe {
        let ptr = sigabbrev_np(signum as c_int);
        if ptr.is_null() {
            return "";
        }
        // `sigabbrev_np` points at an internal static buffer → 'static lifetime.
        CStr::from_ptr(ptr)
            .to_str()
            .expect("glibc never returns non-UTF-8")
    }
}

#[test]
fn test_demangle() {
    assert_eq!("std::cout", demangle("_ZSt4cout").unwrap());
}
