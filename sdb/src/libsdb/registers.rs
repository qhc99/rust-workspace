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
use extended::Extended;
use nix::libc::user;
use std::fmt::Display;
use std::fmt::Write;
use std::rc::Rc;
use std::rc::Weak;

#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct User(pub user);

unsafe impl Zeroable for User {}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct F80(pub Extended);

impl Display for F80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_f64())
    }
}

unsafe impl Pod for F80 {}

unsafe impl Zeroable for F80 {}

impl F80 {
    pub fn new(value: f64) -> Self {
        Self(Extended::from(value))
    }
}

#[derive(Debug)]
pub struct Registers {
    pub data: User,
    process: Weak<Process>,
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
    Float(f32),
    Double(f64),
    LongDouble(F80), // 80 bit extended precision
    Byte64(Byte64),
    Byte128(Byte128),
}

macro_rules! format_register_value {
    ($this:ident,
        {
            $($int_enum:ident => $int_ty:ty );+ $(;)?
        },
        {
            $($float_enum:ident);+ $(;)?
        },
        {
            $($vec_enum:ident);+ $(;)?
        }
    ) => {
        match $this {
            $(
                RegisterValue::$int_enum(v) => {
                    let width = std::mem::size_of::<$int_ty>() * 2 + 2;
                    format!("{:#0width$x}", v, width = width)
                }
            )+
            $(
                RegisterValue::$float_enum(v) => format!("{v}"),
            )+
            $(
                RegisterValue::$vec_enum(v) => {
                    let mut out = String::with_capacity(v.len() * 6 + 2);
                    out.push('[');
                    for (i, v) in v.iter().enumerate() {
                        if i != 0 {
                            out.push(',');
                        }
                        write!(out, "{:#04x}", v).unwrap();
                    }
                    out.push(']');
                    out
                }
            )+
        }
    };
}

impl Display for RegisterValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = format_register_value!(self, {
            U8 => u8;
            U16 => u16;
            U32 => u32;
            U64 => u64;
            I8 => i8;
            I16 => i16;
            I32 => i32;
            I64 => i64;
        },
        { Float; Double; LongDouble},
        { Byte64; Byte128 });
        write!(f, "{v}")
    }
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
impl_register_value_conversion!(f32, Float);
impl_register_value_conversion!(f64, Double);
impl_register_value_conversion!(F80, LongDouble);
impl_register_value_conversion!(Byte64, Byte64);
impl_register_value_conversion!(Byte128, Byte128);

macro_rules! write_cases {
    ( $src:ident, $dest:ident, $info:ident, $( $variant:ident => $ty:ty ),+ $(,)? ) => {
        match $src {
            $(
                RegisterValue::$variant(v)
                    if size_of::<$ty>() <= $info.size => {
                        $dest.copy_from_slice(&to_byte128(v)[..$info.size]);
                    }
            )+
            _ => panic!("register::write called with mismatched register and value sizes"),
        }
    };
}

impl Registers {
    pub fn new(proc: &Rc<Process>) -> Self {
        Self {
            data: User::zeroed(),
            process: Rc::downgrade(proc),
        }
    }
    pub fn read(&self, info: &RegisterInfo) -> Result<RegisterValue, SdbError> {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &self.data as *const _ as *const u8,
                std::mem::size_of_val(&self.data),
            )
        };
        match info.format {
            RegisterFormat::UInt => match info.size {
                1 => Ok(RegisterValue::U8(from_bytes::<u8>(&bytes[info.offset..]))),
                2 => Ok(RegisterValue::U16(from_bytes::<u16>(&bytes[info.offset..]))),
                4 => Ok(RegisterValue::U32(from_bytes::<u32>(&bytes[info.offset..]))),
                8 => Ok(RegisterValue::U64(from_bytes::<u64>(&bytes[info.offset..]))),
                _ => SdbError::err("Unexpected register size"),
            },
            RegisterFormat::DoubleFloat => Ok(RegisterValue::Double(from_bytes::<f64>(
                &bytes[info.offset..],
            ))),
            RegisterFormat::LongDouble => Ok(RegisterValue::LongDouble(from_bytes::<F80>(
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

    pub fn write(&mut self, info: &RegisterInfo, value: RegisterValue) -> Result<(), SdbError> {
        let bytes: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                &mut self.data as *mut _ as *mut u8,
                std::mem::size_of_val(&self.data),
            )
        };
        let dest = &mut bytes[info.offset..info.offset + info.size];

        write_cases!(
            value, dest, info,
            /* unsigned  */ U8 => u8,   U16 => u16, U32 => u32, U64 => u64,
            /* signed    */ I8 => i8,   I16 => i16, I32 => i32, I64 => i64,
            /* floats    */ Float => f32, Double => f64, LongDouble => F80,
            /* vectors   */ Byte64 => Byte64, Byte128 => Byte128,
        );
        if info.type_ == RegisterType::Fpr {
            self.process
                .upgrade()
                .unwrap()
                .write_fprs(&mut self.data.0.i387)?;
        } else {
            let aligned_offset = info.offset & !0b111;
            self.process
                .upgrade()
                .unwrap()
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
