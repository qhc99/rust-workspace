use super::register_info::RegisterFormat;
use super::registers::F80;
use super::sdb_error::SdbError;
use super::{register_info::RegisterInfo, registers::RegisterValue};
use std::str::FromStr;

pub fn parse_register_value(info: &RegisterInfo, text: &str) -> Result<RegisterValue, SdbError> {
    match info.format {
        RegisterFormat::UInt => {
            let digits = if text.starts_with("0x") {
                &text[2..]
            } else {
                &text
            };
            match info.size {
                1 => Ok(RegisterValue::U8(
                    u8::from_str_radix(digits, 16).map_err(|_| SdbError::new("Invalid format"))?,
                )),
                2 => Ok(RegisterValue::U16(
                    u16::from_str_radix(digits, 16).map_err(|_| SdbError::new("Invalid format"))?,
                )),
                4 => Ok(RegisterValue::U32(
                    u32::from_str_radix(digits, 16).map_err(|_| SdbError::new("Invalid format"))?,
                )),
                8 => Ok(RegisterValue::U64(
                    u64::from_str_radix(digits, 16).map_err(|_| SdbError::new("Invalid format"))?,
                )),
                _ => SdbError::err("Invalid format"),
            }
        }
        RegisterFormat::DoubleFloat => Ok(RegisterValue::Double(
            f64::from_str(text).map_err(|_| SdbError::new("Invalid format"))?,
        )),
        RegisterFormat::LongDouble => Ok(RegisterValue::LongDouble(F80::new(
            f64::from_str(text).map_err(|_| SdbError::new("Invalid format"))?,
        ))),
        RegisterFormat::Vector => match info.size {
            8 => todo!(),
            16 => todo!(),
            _ => SdbError::err("Invalid format"),
        },
    }
}
