use cpp_demangle::Symbol;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

pub fn demangle(name: &str) -> Option<String> {
    let sym = Symbol::new(name);
    if let Ok(sym) = sym {
        return Some(sym.to_string());
    }
    None
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
