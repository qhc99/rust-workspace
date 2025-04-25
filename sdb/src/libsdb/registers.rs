use std::cell::RefCell;
use std::rc::Weak;

use super::register_info::RegisterType;

use super::register_info::RegisterFormat;

use super::sdb_error::SdbError;

use super::bit::as_bytes;
use super::bit::as_bytes_mut;
use super::bit::from_bytes;
use super::bit::to_byte128;
use super::process::Process;
use super::register_info::RegisterId;
use super::register_info::RegisterInfo;
use super::register_info::register_info_by_id;
use super::types::{Byte64, Byte128};
use bytemuck::AnyBitPattern;
use bytemuck::NoUninit;
use bytemuck::Pod;
use bytemuck::Zeroable;
use nix::libc::user;
use softfloat_wrapper::F128;
use std::mem::zeroed;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct User(pub user);

unsafe impl NoUninit for User {}

unsafe impl AnyBitPattern for User {}

unsafe impl Zeroable for User {}

impl Default for User {
    fn default() -> Self {
        // SAFETY: all-zero is a valid bit-pattern for `libc::user`
        unsafe { Self(zeroed()) }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct f128(pub F128);

impl From<f32> for f128 {
    fn from(value: f32) -> Self {
        Self(F128::from_f32(value))
    }
}

impl From<f64> for f128 {
    fn from(value: f64) -> Self {
        Self(F128::from_f64(value))
    }
}

unsafe impl Zeroable for f128 {}

unsafe impl Pod for f128 {}

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
    F128(f128),
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
impl_from_register_value!(f128, F128);
impl_from_register_value!(Byte64, Byte64);
impl_from_register_value!(Byte128, Byte128);

impl Registers {
    pub fn new(proc: Weak<RefCell<Process>>) -> Self {
        Self {
            data: User::default(),
            process: proc,
        }
    }
    fn read(&self, info: &RegisterInfo) -> Result<RegisterValue, SdbError> {
        let bytes = as_bytes(&self.data);
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
            RegisterFormat::LongDouble => Ok(RegisterValue::F128(from_bytes::<f128>(
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

    fn write(&mut self, info: &RegisterInfo, mut value: RegisterValue) -> Result<(), SdbError> {
        let bytes = as_bytes_mut(&mut self.data);
        let slice = &mut bytes[info.offset..info.offset + info.size];
        match &mut value {
            RegisterValue::U8(v) if size_of::<u8>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::U16(v) if size_of::<u16>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::U32(v) if size_of::<u32>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::U64(v) if size_of::<u64>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::I8(v) if size_of::<i8>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::I16(v) if size_of::<i16>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::I32(v) if size_of::<i32>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::I64(v) if size_of::<i64>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::F32(v) if size_of::<f32>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::F64(v) if size_of::<f64>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::F128(v) if size_of::<f128>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::Byte64(v) if size_of::<Byte64>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            RegisterValue::Byte128(v) if size_of::<Byte128>() == info.size => {
                slice.copy_from_slice(as_bytes(v));
            }
            _ => panic!("register::write called with mismatched register and value sizes"),
        }
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
                .write_user_area(info.offset, from_bytes(&bytes[..aligned_offset]))?;
        }

        Ok(())
    }

    pub fn read_by_id_as<T>(&self, id: RegisterId) -> Result<T, SdbError>
    where
        T: From<RegisterValue>,
    {
        let info = register_info_by_id(id)?;
        let value = self.read(&info)?;
        Ok(T::from(value))
    }

    pub fn write_by_id(&mut self, id: RegisterId, value: RegisterValue) -> Result<(), SdbError> {
        let info = register_info_by_id(id)?;
        self.write(&info, value)?;
        Ok(())
    }
}

pub trait Widen {
    fn widen(self, info: &RegisterInfo) -> Byte128;
}

macro_rules! impl_widen_float {
    ($($t:ty),+ $(,)?) => {$(
        impl Widen for $t {
            #[inline]
            fn widen(self, info: &RegisterInfo) -> Byte128 {
                match info.format {
                    RegisterFormat::DoubleFloat => to_byte128(self as f64),
                    RegisterFormat::LongDouble  => to_byte128(f128::from(self)),
                    _                           => panic!("Unhandled match"),
                }
            }
        }
    )+};
}

impl_widen_float!(f32, f64);

macro_rules! impl_widen_signed {
    ($($t:ty),+ $(,)?) => {$(
        impl Widen for $t {
            #[inline]
            fn widen(self, info: &RegisterInfo) -> Byte128 {
                if info.format == RegisterFormat::UInt {
                    match info.size {
                        2 => to_byte128(self as i16),
                        4 => to_byte128(self as i32),
                        8 => to_byte128(self as i64),
                        _ => panic!("Unhandled match"),
                    }
                } else {
                    panic!("Unhandled match")
                }
            }
        }
    )+};
}

impl_widen_signed!(i8, i16, i32, i64);

macro_rules! impl_widen_identity {
    ($($t:ty),+) => {$(
        impl Widen for $t {
            #[inline]
            fn widen(self, _info: &RegisterInfo) -> Byte128 {
                to_byte128(self)
            }
        }
    )+};
}

impl_widen_identity!(u8, u16, u32, u64, f128, Byte64, Byte128);

#[inline]
pub fn widen<T: Widen>(info: &RegisterInfo, value: T) -> Byte128 {
    value.widen(info)
}
