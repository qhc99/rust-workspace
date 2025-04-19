use core::mem::offset_of;
use core::mem::size_of;
use libc::user;
use libc::user_regs_struct;
use libc::user_fpregs_struct;
use nix::libc;
use once_cell::sync::Lazy;
use regex::Regex;


enum RegisterId {}

static REGS_INFO: &str = include_str!("../../resource/reg_info.txt");

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
        mem::size_of_val(field)
    }};
}

macro_rules! fpr_size {
    ($reg:ident) => {
        sizeof_field!(user_fpregs_struct, reg)
    };
}

static FPR_DEFS: Lazy<Vec<(String, String, String, String, String, String)>> = Lazy::new(|| {
    // Capture 3 groups: name, number, alias
    let mut res = Vec::<(String, String, String, String, String, String)>::new();
    
    let re = Regex::new(r"DEFINE_GPR_64\((.+?),(.+?)\)").expect("regex compilation failed");
    re.captures_iter(REGS_INFO).for_each(|cap| {
        let name = cap.get(1).unwrap().as_str().trim();
        let dwarf_id = cap.get(2).unwrap().as_str().trim();
        res.push((
            name.to_string(),
            dwarf_id.to_string(),
            "8".to_string(),
            format!("gpr_offset!({name})"),
            "RegisterType::Gpr".to_string(),
            "RegisterFormat::Uint".to_string(),
        ));
    });

    let re = Regex::new(r"DEFINE_GPR_32\((.+?),(.+?)\)").expect("regex compilation failed");
    re.captures_iter(REGS_INFO).for_each(|cap| {
        let name = cap.get(1).unwrap().as_str().trim();
        let super_ = cap.get(2).unwrap().as_str().trim();
        res.push((
            name.to_string(),
            "-1".to_string(),
            "4".to_string(),
            format!("gpr_offset!({super_})"),
            "RegisterType::SubGpr".to_string(),
            "RegisterFormat::Uint".to_string(),
        ));
    });

    let re = Regex::new(r"DEFINE_GPR_16\((.+?),(.+?)\)").expect("regex compilation failed");
    re.captures_iter(REGS_INFO).for_each(|cap| {
        let name = cap.get(1).unwrap().as_str().trim();
        let super_ = cap.get(2).unwrap().as_str().trim();
        res.push((
            name.to_string(),
            "-1".to_string(),
            "2".to_string(),
            format!("gpr_offset!({super_})"),
            "RegisterType::SubGpr".to_string(),
            "RegisterFormat::Uint".to_string(),
        ));
    });

    let re = Regex::new(r"DEFINE_GPR_8H\((.+?),(.+?)\)").expect("regex compilation failed");
    re.captures_iter(REGS_INFO).for_each(|cap| {
        let name = cap.get(1).unwrap().as_str().trim();
        let super_ = cap.get(2).unwrap().as_str().trim();
        res.push((
            name.to_string(),
            "-1".to_string(),
            "1".to_string(),
            format!("gpr_offset!({super_})+1"),
            "RegisterType::SubGpr".to_string(),
            "RegisterFormat::Uint".to_string(),
        ));
    });

    let re = Regex::new(r"DEFINE_GPR_8L\((.+?),(.+?)\)").expect("regex compilation failed");
    re.captures_iter(REGS_INFO).for_each(|cap| {
        let name = cap.get(1).unwrap().as_str().trim();
        let super_ = cap.get(2).unwrap().as_str().trim();
        res.push((
            name.to_string(),
            "-1".to_string(),
            "1".to_string(),
            format!("gpr_offset!({super_})"),
            "RegisterType::SubGpr".to_string(),
            "RegisterFormat::Uint".to_string(),
        ));
    });

    let re = Regex::new(r"DEFINE_FPR\((.+?),(.+?),(.+?)\)").expect("regex compilation failed");
    re.captures_iter(REGS_INFO).for_each(|cap| {
        let name = cap.get(1).unwrap().as_str().trim();
        let dwarf_id = cap.get(2).unwrap().as_str().trim();
        let user_name = cap.get(2).unwrap().as_str().trim();
        res.push((
            name.to_string(),
            dwarf_id.to_string(),
            format!("fpr_size!({user_name})").to_string(),
            format!("fpr_offset!({user_name})"),
            "RegisterType::Fpr".to_string(),
            "RegisterFormat::Uint".to_string(),
        ));
    });

    return res;
});

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
    name: String,
    dwarf_id: i32,
    size: usize,
    offset: usize,
    type_: RegisterType,
    format: RegisterFormat,
}

static GRegisterInfos: &[RegisterInfo] = &[];

fn t(){
    
}
