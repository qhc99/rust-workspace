use super::register_info::RegisterFormat;
use super::registers::F80;
use super::sdb_error::SdbError;
use super::{register_info::RegisterInfo, registers::RegisterValue};
use super::traits::FromLowerHexStr;
use std::str::FromStr;

macro_rules! match_parse_int {
    ($size:expr, $digits:expr, {
        $($num:expr => $Variant:ident, $Ty:ty);+ $(;)?
    }) => {
        match $size {
            $(
                $num => Ok(RegisterValue::$Variant(
                    <$Ty>::from_lower_hex_radix($digits, 16)?,
                )),
            )+
            _ => SdbError::err("Invalid format"),
        }
    };
}

macro_rules! match_parse_vector {
    ($size:expr, $text:expr, {
        $($num:expr => $Variant:ident);+ $(;)?
    }) => {
        match $size {
            $(
                $num => {
                    let parse_res = parse_vector($text)?;
                    let bytes: [u8; $num] = parse_res
                        .try_into()
                        .map_err(|_| SdbError::new_err("Invalid format"))?;
                    Ok(RegisterValue::$Variant(bytes))
                }
            )+
            _ => SdbError::err("Invalid format"),
        }
    };
}

pub fn parse_vector(text: &str) -> Result<Vec<u8>, SdbError> {
    if !text.ends_with("]") || !text.starts_with("[") {
        return SdbError::err("Not vector format");
    }
    let elements = &text[1..(text.len() - 1)];
    let digits = elements
        .split(",")
        .map(|data| {
            let data = data.trim();
            if data.starts_with("0x") && data.len() == 4 {
                u8::from_str_radix(&data[2..4], 16).ok()
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if !digits.iter().all(|d| d.is_some()) {
        return SdbError::err("Invalid vector elements format");
    }

    Ok(digits.into_iter().map(|d| d.unwrap()).collect())
}

pub fn parse_register_value(info: &RegisterInfo, text: &str) -> Result<RegisterValue, SdbError> {
    match info.format {
        RegisterFormat::UInt => {
            match_parse_int!(info.size, text, {
                1 => U8, u8;
                2 => U16, u16;
                4 => U32, u32;
                8 => U64, u64;
            })
        }
        RegisterFormat::DoubleFloat => Ok(RegisterValue::Double(
            f64::from_str(text).map_err(|_| SdbError::new_err("Invalid format"))?,
        )),
        RegisterFormat::LongDouble => Ok(RegisterValue::LongDouble(F80::new(
            f64::from_str(text).map_err(|_| SdbError::new_err("Invalid format"))?,
        ))),
        RegisterFormat::Vector => match_parse_vector!(info.size, text, {
            8 => Byte64;
            16=> Byte128;
        }),
    }
}
