use super::types::Byte64;
use super::types::Byte128;
use bytemuck::NoUninit;
use bytemuck::Pod;
use bytemuck::bytes_of;
use bytemuck::pod_read_unaligned;
use std::ffi::CStr;
use std::ffi::c_char;
use std::mem;

pub fn from_bytes<To: Pod>(bytes: &[u8]) -> To {
    let slice = &bytes[..size_of::<To>()];
    pod_read_unaligned(slice)
}

pub fn to_byte_span<T: Pod>(src: &T) -> &[u8] {
    bytes_of(src)
}

pub fn to_byte_vec<T: Pod>(src: &T) -> Vec<u8> {
    let src_bytes = bytes_of(src);
    src_bytes.to_vec()
}

pub fn to_byte64<T: NoUninit>(src: T) -> Byte64 {
    let mut out: Byte64 = [0; 8];
    let src_bytes = bytes_of(&src);
    out[..src_bytes.len()].copy_from_slice(src_bytes);
    out
}

pub fn to_byte128<T: NoUninit>(src: T) -> Byte128 {
    let mut out: Byte128 = [0; 16];
    let src_bytes = bytes_of(&src);
    out[..src_bytes.len()].copy_from_slice(src_bytes);
    out
}

pub fn from_array_bytes<T: Pod>(data: &[u8]) -> Vec<T> {
    let type_size = mem::size_of::<T>();
    let count = data.len() / type_size;
    assert_eq!(count * type_size, data.len());
    let mut vec = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * mem::size_of::<T>();
        let obj: T = pod_read_unaligned(&data[offset..offset + mem::size_of::<T>()]);
        vec.push(obj);
    }
    vec
}

pub fn cstr_view(data: &[u8]) -> &str {
    assert!(data.iter().any(|d| { *d == 0 }), "Cannot find c-string");
    let ptr = data.as_ptr() as *const c_char;
    unsafe { CStr::from_ptr(ptr).to_str().unwrap() }
}

pub fn memcpy_bits(
    dest: &mut [u8],
    mut dest_bit: u32,
    src: &[u8],
    mut src_bit: u32,
    mut n_bits: u32,
) {
    while n_bits > 0 {
        let dest_mask = 1u8 << (dest_bit % 8);
        dest[(dest_bit / 8) as usize] &= !dest_mask;

        let src_mask = 1u8 << (src_bit % 8);
        let corresponding_src_bit_set = src[(src_bit / 8) as usize] & src_mask;

        if corresponding_src_bit_set != 0 {
            dest[(dest_bit / 8) as usize] |= dest_mask;
        }

        n_bits -= 1;
        src_bit += 1;
        dest_bit += 1;
    }
}
