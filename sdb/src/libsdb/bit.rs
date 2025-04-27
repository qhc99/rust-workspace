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

pub fn as_bytes<T: NoUninit + 'static>(from: &T) -> &[u8] {
    bytes_of(from)
}

pub fn as_bytes_mut<T: AnyBitPattern + NoUninit + 'static>(from: &mut T) -> &mut [u8] {
    bytes_of_mut(from)
}

pub fn to_byte64<T: Pod>(src: T) -> Byte64 {
    let mut out: Byte64 = [0; 8];
    let src_bytes = bytes_of(&src);
    out[..src_bytes.len()].copy_from_slice(src_bytes);
    out
}

pub fn to_byte128<T: Pod>(src: T) -> Byte128 {
    let mut out: Byte128 = [0; 16];
    let src_bytes = bytes_of(&src);
    out[..src_bytes.len()].copy_from_slice(src_bytes);
    out
}
