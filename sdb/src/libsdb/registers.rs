use super::sdb_error::SdbError;

use super::process::Process;
use super::register_info::RegisterId;
use super::register_info::RegisterInfo;
use super::register_info::register_info_by_id;
use super::types::{Byte64, Byte128};
use nix::libc::user;
use softfloat_wrapper::F128;

struct Registers<'a> {
    data: user,
    process: &'a Process,
}

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
    F128(F128),
    Byte64(Byte64),
    Byte128(Byte128),
}

/* --- blanket impls for the primitive types you actually care about --- */
macro_rules! impl_from_register_value {
    ($t:ty, $p:ident) => {
        impl From<RegisterValue> for $t {
            fn from(val: RegisterValue) -> Self {
                match val {
                    RegisterValue::$p(inner) => inner as $t,
                    _ => panic!("Unkown RegisterValue"),
                }
            }
        }
    };
}

impl_from_register_value!(u8, U8);
impl_from_register_value!(u16, U16);
impl_from_register_value!(u32, U32);
impl_from_register_value!(u64, U64);
impl_from_register_value!(i8, I8);
impl_from_register_value!(i16, I16);
impl_from_register_value!(i32, I32);
impl_from_register_value!(i64, I64);
impl_from_register_value!(f32, F32);
impl_from_register_value!(f64, F64);
impl_from_register_value!(F128, F128);
impl_from_register_value!(Byte64, Byte64);
impl_from_register_value!(Byte128, Byte128);

impl Registers<'_> {
    fn read(&self, info: &RegisterInfo) -> RegisterValue {
        todo!()
    }
    fn write(&self, info: &RegisterInfo, value: RegisterValue) {
        todo!()
    }

    pub fn read_by_id_as<T>(&self, id: RegisterId) -> Result<T, SdbError>
    where
        T: From<RegisterValue>,
    {
        let info = register_info_by_id(id)?;
        let value = self.read(&info);
        Ok(T::from(value))
    }

    pub fn write_by_id(&self, id: RegisterId, value: RegisterValue) -> Result<(), SdbError> {
        let info = register_info_by_id(id)?;
        self.write(&info, value);
        Ok(())
    }
}
