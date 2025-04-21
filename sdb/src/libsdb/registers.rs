use super::register_info::RegisterInfo;
use super::types::{Byte64, Byte128};

struct Registers {}

enum RegisterValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    F128(f64), // TODO
    Byte64(Byte64),
    Byte128(Byte128),
}

impl Registers {
    fn read(&self, info: &RegisterInfo) -> RegisterValue {
        todo!()
    }
    fn write(&self, info: &RegisterInfo, value: RegisterValue) {
        todo!()
    }
}
