use regex::bytes::Regex;

use super::register_info::RegisterFormat;
use super::registers::F80;
use super::sdb_error::SdbError;
use super::{register_info::RegisterInfo, registers::RegisterValue};
use std::str::FromStr;

macro_rules! parse_int {
    ($size:expr, $digits:expr, {
        $($num:expr => $Variant:ident, $Ty:ty);+ $(;)?
    }) => {
        match $size {
            $(
                $num => Ok(RegisterValue::$Variant(
                    <$Ty>::from_str_radix($digits, 16)
                        .map_err(|_| SdbError::new("Invalid format"))?,
                )),
            )+
            _ => SdbError::err("Invalid format"),
        }
    };
}

macro_rules! parse_vector {
    ($size:expr, $text:expr, {
        $($num:expr => $Variant:ident);+ $(;)?
    }) => {
        match $size {
            $(
                $num => {
                    let re_pat = format!("\\[(0x\\w{}\\s*,\\s*){}\\]", 2, $num);
                    let re = Regex::new(&re_pat).unwrap();
                    let re_bytes = Regex::new(r"0x(\w{2})").unwrap();
                    return if re.is_match($text.as_bytes()) {
                        let parse_res: Vec<_> = re_bytes
                            .captures(&$text.as_bytes())
                            .unwrap()
                            .iter()
                            .map(|digits| {
                                u8::from_str_radix(
                                    std::str::from_utf8(digits.unwrap().as_bytes()).unwrap(),
                                    16,
                                )
                            })
                            .collect();
                        if parse_res.iter().all(|data| data.is_ok()) {
                            let bytes: [u8; $num] = parse_res
                                .into_iter()
                                .map(|data| data.unwrap())
                                .collect::<Vec<_>>()
                                .try_into()
                                .unwrap();
                            Ok(RegisterValue::$Variant(bytes))
                        } else {
                            SdbError::err("Invalid format")
                        }
                    } else {
                        SdbError::err("Invalid format")
                    };
                }
            )+
            _ => SdbError::err("Invalid format"),
        }
    };
}

pub fn parse_register_value(info: &RegisterInfo, text: &str) -> Result<RegisterValue, SdbError> {
    match info.format {
        RegisterFormat::UInt => {
            let digits = text.strip_prefix("0x").unwrap_or(text);
            parse_int!(info.size, digits, {
                1 => U8, u8;
                2 => U16, u16;
                4 => U32, u32;
                8 => U64, u64;
            })
        }
        RegisterFormat::DoubleFloat => Ok(RegisterValue::Double(
            f64::from_str(text).map_err(|_| SdbError::new("Invalid format"))?,
        )),
        RegisterFormat::LongDouble => Ok(RegisterValue::LongDouble(F80::new(
            f64::from_str(text).map_err(|_| SdbError::new("Invalid format"))?,
        ))),
        RegisterFormat::Vector => parse_vector!(info.size, text, {
            8 => Byte64;
            16=> Byte128;
        }),
    }
}
