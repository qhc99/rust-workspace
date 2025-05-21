use super::sdb_error::SdbError;
use nix::libc::c_long;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use syscall_numbers::x86_64::sys_call_name;

const MAX_SYSCALL_NUMBER: i64 = 0x1ff;

static SYSCALL_NAME_TO_NUM: Lazy<HashMap<&'static str, c_long>> = Lazy::new(|| {
    let mut map = HashMap::with_capacity(MAX_SYSCALL_NUMBER as usize);
    for n in 0..=MAX_SYSCALL_NUMBER {
        if let Some(name) = sys_call_name(n) {
            if !name.is_empty() {
                map.insert(name, n as c_long);
            }
        }
    }
    map
});

pub fn syscall_name_to_id(name: &str) -> Result<c_long, SdbError> {
    SYSCALL_NAME_TO_NUM
        .get(name)
        .copied()
        .ok_or(SdbError::new_err(&format!("No such syscall name: {name}")))
}

pub fn syscall_id_to_name(id: c_long) -> Result<&'static str, SdbError> {
    sys_call_name(id).ok_or(SdbError::new_err(&format!("No such syscall id: {id}")))
}
