use core::mem::offset_of;
use libc::user;
use libc::user_fpregs_struct;
use libc::user_regs_struct;
use nix::libc;
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

enum RegisterType {
    Gpr, // General purpose register
    SubGpr,
    Fpr, // Float point register
    Dr,  // Debug register
}

enum RegisterFormat {
    Uint,
    DoubleFloat,
    LongDouble,
    Vector,
}

struct RegisterInfo {
    id: RegisterId,
    name: &'static str,
    dwarf_id: i32,
    size: usize,
    offset: usize,
    type_: RegisterType,
    format: RegisterFormat,
}

