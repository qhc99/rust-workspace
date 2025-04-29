use core::mem::offset_of;
use libc::user;
use libc::user_fpregs_struct;
use libc::user_regs_struct;
use nix::libc;
use num_enum::TryFromPrimitive;
use register_codegen::generate_registers;

macro_rules! gpr_offset {
    ($reg:ident) => {
        offset_of!(user, regs) + offset_of!(user_regs_struct, $reg)
    };
}

macro_rules! fpr_offset {
    ($reg:ident) => {
        offset_of!(user, i387) + offset_of!(user_fpregs_struct, $reg)
    };
}

macro_rules! sizeof_field {
    ($struct:ty, $field:ident) => {{
        let uninit = std::mem::MaybeUninit::<$struct>::uninit();
        let base = uninit.as_ptr();
        let field = unsafe { &(*base).$field };
        core::mem::size_of_val(field)
    }};
}

macro_rules! fpr_size {
    ($reg:ident) => {
        sizeof_field!(user_fpregs_struct, $reg)
    };
}

generate_registers!("sdb/resource/reg_info.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterType {
    Gpr, // General purpose register
    SubGpr,
    Fpr, // Float point register
    Dr,  // Debug register
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterFormat {
    UInt,
    DoubleFloat,
    LongDouble,
    Vector,
}

#[derive(Debug, Clone, Copy)]
pub struct RegisterInfo {
    pub id: RegisterId,
    pub name: &'static str,
    pub dwarf_id: i32,
    pub size: usize,
    pub offset: usize,
    pub type_: RegisterType,
    pub format: RegisterFormat,
}

use super::sdb_error::SdbError; // adjust this to your actual module path

pub fn register_info_by_id(id: RegisterId) -> Result<RegisterInfo, SdbError> {
    GRegisterInfos
        .iter()
        .find(|info| info.id == id)
        .copied()
        .ok_or_else(|| SdbError::new("Can't find register info"))
}

pub fn register_info_by_name(name: &str) -> Result<RegisterInfo, SdbError> {
    GRegisterInfos
        .iter()
        .find(|info| info.name == name)
        .copied()
        .ok_or_else(|| SdbError::new("Can't find register info"))
}

pub fn register_info_by_dwarf(dwarf_id: i32) -> Result<RegisterInfo, SdbError> {
    GRegisterInfos
        .iter()
        .find(|info| info.dwarf_id == dwarf_id)
        .copied()
        .ok_or_else(|| SdbError::new("Can't find register info"))
}

#[ignore = "Manual"]
#[test]
fn print_codegen() {
    for i in GRegisterInfos {
        println!("{:?}", i);
    }
}
