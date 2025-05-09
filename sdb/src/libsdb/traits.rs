use super::sdb_error::SdbError;
use super::{breakpoint_site::IdType, types::VirtualAddress};

pub trait StoppointTrait {
    fn id(&self) -> IdType;

    fn at_address(&self, addr: VirtualAddress) -> bool;

    fn disable(&mut self) -> Result<(), SdbError>;

    fn address(&self) -> VirtualAddress;

    fn enable(&mut self) -> Result<(), SdbError>;
}

pub trait FromLowerHexStr: Sized {
    fn from_lower_hex_radix(s: &str, radix: u32) -> Result<Self, SdbError>;

    fn from_lower_hex(s: &str) -> Result<Self, SdbError> {
        Self::from_lower_hex_radix(s, 16)
    }
}

macro_rules! impl_from_lower_hex {
    ($($Ty:ty );+ $(;)?) => {
        $(
            impl FromLowerHexStr for $Ty {
                fn from_lower_hex_radix(text: &str, radix: u32) -> Result<$Ty, SdbError>{
                    let digits = text.strip_prefix("0x").unwrap_or(text);
                    <$Ty>::from_str_radix(digits, radix).map_err(|_|{SdbError::new_err("Invalid format")})
                }

                fn from_lower_hex(text: &str) -> Result<$Ty, SdbError>{
                    text.parse::<$Ty>().map_err(|_|{SdbError::new_err("Invalid format")})
                }
            }
        )+
    };
}

impl_from_lower_hex!(u8;u16;u32;u64;u128;usize;i8;i16;i32;i64;i128);
