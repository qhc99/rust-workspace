use super::bit::AsBytes;
use super::bit::from_bytes;
use super::bit::to_byte128;
use super::process::Process;
use super::register_info::RegisterFormat;
use super::register_info::RegisterId;
use super::register_info::RegisterInfo;
use super::register_info::RegisterType;
use super::register_info::register_info_by_id;
use super::sdb_error::SdbError;
use super::types::{Byte64, Byte128};
use bytemuck::Pod;
use bytemuck::Zeroable;
use nix::libc::user;
use std::cell::RefCell;
use std::mem::zeroed;
use std::rc::Weak;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct User(pub user);

unsafe impl Zeroable for User {}

impl Default for User {
    fn default() -> Self {
        unsafe { Self(zeroed()) }
    }
}
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct NightlyF128(pub f128);

impl NightlyF128 {
    pub fn new(val: f128) -> Self {
        Self(val)
    }
}

unsafe impl Pod for NightlyF128 {}

unsafe impl Zeroable for NightlyF128 {}

pub struct Registers {
    pub data: User,
    process: Weak<RefCell<Process>>,
}

pub enum RegisterValue {
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
    F128(NightlyF128),
    Byte64(Byte64),
    Byte128(Byte128),
}

/* --- blanket impls for the primitive types you actually care about --- */
macro_rules! impl_register_value_conversion {
    ($t:ty, $p:ident) => {
        impl From<RegisterValue> for $t {
            fn from(val: RegisterValue) -> Self {
                match val {
                    RegisterValue::$p(inner) => inner as $t,
                    _ => panic!("Unkown RegisterValue"),
                }
            }
        }

        impl From<$t> for RegisterValue {
            #[inline]
            fn from(val: $t) -> Self {
                RegisterValue::$p(val)
            }
        }
    };
}

impl_register_value_conversion!(u8, U8);
impl_register_value_conversion!(u16, U16);
impl_register_value_conversion!(u32, U32);
impl_register_value_conversion!(u64, U64);
impl_register_value_conversion!(i8, I8);
impl_register_value_conversion!(i16, I16);
impl_register_value_conversion!(i32, I32);
impl_register_value_conversion!(i64, I64);
impl_register_value_conversion!(f32, F32);
impl_register_value_conversion!(f64, F64);
impl_register_value_conversion!(NightlyF128, F128);
impl_register_value_conversion!(Byte64, Byte64);
impl_register_value_conversion!(Byte128, Byte128);

macro_rules! write_cases {
    ( $value:ident, $slice:ident, $info:ident, $( $variant:ident => $ty:ty ),+ $(,)? ) => {
        match $value {
            $(
                RegisterValue::$variant(v)
                    if size_of::<$ty>() <= $info.size => {
                        $slice.copy_from_slice(&to_byte128(v)[..$info.size]);
                    }
            )+
            _ => panic!("register::write called with mismatched register and value sizes"),
        }
    };
}

impl Registers {
    pub fn new(proc: Weak<RefCell<Process>>) -> Self {
        Self {
            data: User::default(), // TODO fix
            process: proc,
        }
    }
    fn read(&self, info: &RegisterInfo) -> Result<RegisterValue, SdbError> {
        let bytes = self.data.as_bytes();
        match info.format {
            RegisterFormat::UInt => match info.size {
                1 => Ok(RegisterValue::U8(from_bytes::<u8>(&bytes[info.offset..]))),
                2 => Ok(RegisterValue::U16(from_bytes::<u16>(&bytes[info.offset..]))),
                4 => Ok(RegisterValue::U32(from_bytes::<u32>(&bytes[info.offset..]))),
                8 => Ok(RegisterValue::U64(from_bytes::<u64>(&bytes[info.offset..]))),
                _ => SdbError::err("Unexpected register size"),
            },
            RegisterFormat::DoubleFloat => {
                Ok(RegisterValue::F64(from_bytes::<f64>(&bytes[info.offset..])))
            }
            RegisterFormat::LongDouble => Ok(RegisterValue::F128(from_bytes::<NightlyF128>(
                &bytes[info.offset..],
            ))),
            RegisterFormat::Vector if info.size == 8 => {
                Ok(RegisterValue::Byte64(from_bytes::<Byte64>(
                    &bytes[info.offset..],
                )))
            }
            _ => Ok(RegisterValue::Byte128(from_bytes::<Byte128>(
                &bytes[info.offset..],
            ))),
        }
    }

    fn write(&mut self, info: &RegisterInfo, value: RegisterValue) -> Result<(), SdbError> {
        let bytes = self.data.as_bytes_mut();
        let slice = &mut bytes[info.offset..info.offset + info.size];

        write_cases!(
            value, slice, info,
            /* unsigned  */ U8 => u8,   U16 => u16, U32 => u32, U64 => u64,
            /* signed    */ I8 => i8,   I16 => i16, I32 => i32, I64 => i64,
            /* floats    */ F32 => f32, F64 => f64, F128 => NightlyF128,
            /* vectors   */ Byte64 => Byte64, Byte128 => Byte128,
        );
        if info.type_ == RegisterType::Fpr {
            self.process
                .upgrade()
                .unwrap()
                .borrow()
                .write_fprs(&mut self.data.0.i387)?;
        } else {
            let aligned_offset = info.offset & !0b111;
            self.process
                .upgrade()
                .unwrap()
                .borrow()
                .write_user_area(info.offset, from_bytes::<u64>(&bytes[aligned_offset..]))?;
        }

        Ok(())
    }

    pub fn read_by_id_as<T: From<RegisterValue>>(&self, id: RegisterId) -> Result<T, SdbError> {
        let info = register_info_by_id(id)?;
        let value = self.read(&info)?;
        Ok(T::from(value))
    }

    pub fn write_by_id<T: Into<RegisterValue>>(
        &mut self,
        id: RegisterId,
        value: T,
    ) -> Result<(), SdbError> {
        let info = register_info_by_id(id)?;
        self.write(&info, value.into())?;
        Ok(())
    }
}
