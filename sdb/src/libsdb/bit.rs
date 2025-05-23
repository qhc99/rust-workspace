use std::ffi::CStr;
use std::ffi::c_char;
use std::mem;
use std::ptr;
use std::slice;

use super::registers::User;
use super::types::Byte64;
use super::types::Byte128;
use bytemuck::AnyBitPattern;
use bytemuck::NoUninit;
use bytemuck::Pod;
use bytemuck::bytes_of;
use bytemuck::bytes_of_mut;
use bytemuck::pod_read_unaligned;

pub fn from_bytes<To: Pod>(bytes: &[u8]) -> To {
    let slice = &bytes[..size_of::<To>()];
    pod_read_unaligned(slice)
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];

    fn as_bytes_mut(&mut self) -> &mut [u8];
}

impl<T: NoUninit + AnyBitPattern + 'static> AsBytes for T {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        bytes_of(self)
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        bytes_of_mut(self)
    }
}

impl AsBytes for User {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const User as *const u8, mem::size_of::<User>()) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self as *const User as *mut u8, mem::size_of::<User>()) }
    }
}

pub fn to_byte64<T: AsBytes>(src: T) -> Byte64 {
    let mut out: Byte64 = [0; 8];
    let src_bytes = src.as_bytes();
    out[..src_bytes.len()].copy_from_slice(src_bytes);
    out
}

pub fn to_byte128<T: AsBytes>(src: T) -> Byte128 {
    let mut out: Byte128 = [0; 16];
    let src_bytes = src.as_bytes();
    out[..src_bytes.len()].copy_from_slice(src_bytes);
    out
}

/// # Safety
/// Bytes should be valid for type T
pub unsafe fn init_from_bytes<T>(data: &[u8]) -> T {
    let mut obj: T = unsafe { mem::zeroed() };
    let type_size = mem::size_of::<T>();
    assert!(data.len() == type_size);
    unsafe {
        ptr::copy_nonoverlapping(
            data[..type_size].as_ptr(),
            &mut obj as *mut _ as *mut u8,
            type_size,
        );
    }
    return obj;
}

/// # Safety
/// Bytes should be valid for type T
pub unsafe fn init_array_from_bytes<T>(data: &[u8]) -> Vec<T> {
    let type_size = mem::size_of::<T>();
    let count = data.len() / type_size;
    assert_eq!(count * type_size, data.len());
    let mut ret = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * mem::size_of::<T>();
        let obj: T = unsafe { init_from_bytes(&data[offset..mem::size_of::<T>()]) };
        ret.push(obj);
    }
    ret
}

pub fn cstr_view(data: &[u8]) -> &str {
    assert!(data.iter().any(|d| { *d == 0 }), "Cannot find c-string");
    let ptr = data.as_ptr() as *const c_char;
    unsafe { CStr::from_ptr(ptr).to_str().unwrap() }
}
