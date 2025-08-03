#![cfg(test)]
use serial_test::serial;
use std::{
    cell::RefCell,
    collections::HashSet,
    env,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader},
    os::fd::AsRawFd,
    path::PathBuf,
    rc::Rc,
    sync::{LazyLock, Mutex},
};

use libsdb::target::{Target, TargetExt};

use bytes::Bytes;
use gimli::{
    DW_AT_language, DW_AT_location, DW_AT_name, DW_LANG_C_plus_plus, DW_OP_bit_piece,
    DW_OP_const4u, DW_OP_piece, DW_OP_reg16, DW_TAG_subprogram,
};
use libsdb::dwarf::{DwarfExpression, DwarfExpressionResult, DwarfExpressionSimpleLocation};
use libsdb::syscalls::syscall_name_to_id;
use libsdb::{bit::from_bytes, process::SyscallCatchPolicy};
use libsdb::{
    bit::{to_byte64, to_byte128},
    pipe::Pipe,
    process::Process,
    registers::F80,
    types::{Byte64, Byte128},
};
use libsdb::{dwarf::CompileUnitExt, register_info::RegisterId};
use libsdb::{dwarf::CompileUnitRangeList, types::StoppointMode};
use libsdb::{dwarf::DieExt, syscalls::syscall_id_to_name};
use libsdb::{dwarf::LineTableExt, types::VirtualAddress};
use libsdb::{
    elf::Elf,
    process::{ProcessState, SyscallData, TrapType},
    types::FileAddress,
};
use libsdb::{process::ProcessExt, traits::StoppointTrait};
use nix::{
    sys::signal::Signal::{self, SIGTRAP},
    unistd::Pid,
};
use std::{
    io::{self},
    path::Path,
};

use elf::{ElfBytes, endian::AnyEndian};
use regex::Regex;
use std::process::Command;

static LD_PATH_LOCK: Mutex<()> = Mutex::new(());

pub fn append_ld_dir(dir: &str) {
    let _guard = LD_PATH_LOCK.lock().unwrap();
    let mut ld_path = env::var("LD_LIBRARY_PATH").unwrap_or_default();
    if !ld_path.split(':').any(|p| p == dir) {
        ld_path.push(':');
        ld_path.push_str(dir);
    }
    unsafe { env::set_var("LD_LIBRARY_PATH", ld_path) };
}

fn get_process_state(pid: Pid) -> String {
    let pid_num = pid.as_raw();
    let file = File::open(format!("/proc/{pid_num}/stat")).unwrap();
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let idx = line.match_indices(")").into_iter().last().unwrap().0;
    return String::from_utf8_lossy(&line.as_bytes()[idx + 2..idx + 3]).to_string();
}

static LOOP_ASSIGN_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/loop_assign"));
static JUST_EXIT_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/just_exit"));
static REG_WRITE_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/reg_write"));
static REG_READ_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/reg_read"));
static HELLO_SDB_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/hello_sdb"));
static MEMORY_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/memory"));
static ANTI_DEBUGGER_PATH: LazyLock<&Path> =
    LazyLock::new(|| Path::new("resource/bin/anti_debugger"));
static MULTI_THREAD_PATH: LazyLock<&Path> =
    LazyLock::new(|| Path::new("resource/bin/multi_threaded"));
static STEP_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/step"));
static MULTI_CU_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/multi_cu_main"));
static OVERLOADED_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/overloaded"));
static MARSHMALLOW_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/marshmallow"));
static GLOBAL_VARIABLE_PATH: LazyLock<&Path> =
    LazyLock::new(|| Path::new("resource/bin/global_variable"));
static MEMBER_POINTER_PATH: LazyLock<&Path> =
    LazyLock::new(|| Path::new("resource/bin/member_pointer"));
static BLOCKS_PATH: LazyLock<&Path> = LazyLock::new(|| Path::new("resource/bin/blocks"));

#[test]
#[serial]
fn process_attach_success() {
    let target = Process::launch(LOOP_ASSIGN_PATH.as_ref(), false, None).unwrap();
    let _proc = Process::attach(target.pid()).unwrap();
    assert!(get_process_state(target.pid()) == "t");
}

#[test]
#[serial]
fn process_attach_invalid_pid() {
    assert!(Process::attach(Pid::from_raw(0)).is_err());
}

#[test]
#[serial]
fn process_resume_success() {
    let proc = Process::launch(LOOP_ASSIGN_PATH.as_ref(), true, None).unwrap();
    proc.resume(None).ok();
    let status = get_process_state(proc.pid());
    assert!(status == "R" || status == "S");

    let target = Process::launch(LOOP_ASSIGN_PATH.as_ref(), false, None).unwrap();
    let proc = Process::attach(target.pid()).unwrap();
    proc.resume(None).ok();
    let status = get_process_state(proc.pid());
    assert!(status == "R" || status == "S");
}

#[test]
#[serial]
fn process_resume_terminated() {
    let proc = Process::launch(JUST_EXIT_PATH.as_ref(), true, None).unwrap();
    proc.resume(None).ok();
    proc.wait_on_signal(Pid::from_raw(-1)).ok();
    assert!(proc.resume(None).is_err());
}

#[test]
#[serial]
fn write_registers() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let proc =
        Process::launch(REG_WRITE_PATH.as_ref(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    {
        proc.get_registers(None)
            .borrow_mut()
            .write_by_id(RegisterId::rsi, 0xcafecafe_u64, true)
            .unwrap();

        proc.resume(None).unwrap();
        proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "0xcafecafe");
    }

    {
        proc.get_registers(None)
            .borrow_mut()
            .write_by_id(RegisterId::mm0, 0xba5eba11_u64, true)
            .unwrap();

        proc.resume(None).unwrap();
        proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "0xba5eba11")
    }

    {
        proc.get_registers(None)
            .borrow_mut()
            .write_by_id(RegisterId::xmm0, 42.24, true)
            .unwrap();

        proc.resume(None).unwrap();
        proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "42.24");
    }

    {
        proc.get_registers(None)
            .borrow_mut()
            .write_by_id(RegisterId::st0, F80::new(42.24), true)
            .unwrap();
        proc.get_registers(None)
            .borrow_mut()
            .write_by_id(RegisterId::fsw, 0b0011100000000000_u16, true)
            .unwrap();
        proc.get_registers(None)
            .borrow_mut()
            .write_by_id(RegisterId::ftw, 0b0011111111111111_u16, true)
            .unwrap();

        proc.resume(None).unwrap();
        proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "42.24");
    }
}

#[test]
#[serial]
fn read_registers() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let proc = Process::launch(REG_READ_PATH.as_ref(), true, Some(channel.get_write_fd())).unwrap();
    let regs = proc.get_registers(None);
    channel.close_write();

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert!(regs.borrow().read_by_id_as::<u64>(RegisterId::r13).unwrap() == 0xcafecafe_u64);

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert!(regs.borrow().read_by_id_as::<u8>(RegisterId::r13b).unwrap() == 42);

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert!(
        regs.borrow()
            .read_by_id_as::<Byte64>(RegisterId::mm0)
            .unwrap()
            == to_byte64(0xba5eba11_u64)
    );

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert!(
        regs.borrow()
            .read_by_id_as::<Byte128>(RegisterId::xmm0)
            .unwrap()
            == to_byte128(64.125)
    );

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert!(regs.borrow().read_by_id_as::<F80>(RegisterId::st0).unwrap() == F80::new(64.125));
}

#[test]
#[serial]
fn create_breakpoint_site() {
    let proc = Process::launch(LOOP_ASSIGN_PATH.as_ref(), true, None).unwrap();
    let site = proc.create_breakpoint_site(42.into(), false, false);
    assert_eq!(
        VirtualAddress::from(42),
        site.unwrap().upgrade().unwrap().borrow().address()
    );
}

#[test]
#[serial]
fn create_breakpoint_site_id_increase() {
    let proc = Process::launch(LOOP_ASSIGN_PATH.as_ref(), true, None).unwrap();
    let site1 = proc
        .create_breakpoint_site(42.into(), false, false)
        .unwrap();
    assert_eq!(
        VirtualAddress::from(42),
        site1.upgrade().unwrap().borrow().address()
    );

    let site2 = proc
        .create_breakpoint_site(43.into(), false, false)
        .unwrap();
    assert_eq!(
        site2.upgrade().unwrap().borrow().id(),
        site1.upgrade().unwrap().borrow().id() + 1
    );

    let site3 = proc
        .create_breakpoint_site(44.into(), false, false)
        .unwrap();
    assert_eq!(
        site3.upgrade().unwrap().borrow().id(),
        site2.upgrade().unwrap().borrow().id() + 1
    );

    let site4 = proc
        .create_breakpoint_site(45.into(), false, false)
        .unwrap();
    assert_eq!(
        site4.upgrade().unwrap().borrow().id(),
        site3.upgrade().unwrap().borrow().id() + 1
    );
}

#[test]
#[serial]
fn find_breakpoint_sites() {
    let proc = Process::launch(LOOP_ASSIGN_PATH.as_ref(), true, None).unwrap();
    let _ = proc.create_breakpoint_site(42.into(), false, false);
    let _ = proc.create_breakpoint_site(43.into(), false, false);
    let _ = proc.create_breakpoint_site(44.into(), false, false);
    let _ = proc.create_breakpoint_site(45.into(), false, false);

    let s1 = proc
        .breakpoint_sites()
        .borrow()
        .get_by_address(44.into())
        .unwrap();
    assert!(proc.breakpoint_sites().borrow().contains_address(44.into()));
    assert!(s1.borrow().address() == 44.into());

    let s2 = proc
        .breakpoint_sites()
        .borrow()
        .get_by_id(s1.borrow().id() + 1)
        .unwrap();
    assert!(
        proc.breakpoint_sites()
            .borrow()
            .contain_id(s1.borrow().id() + 1)
    );
    assert!(s2.borrow().id() == s1.borrow().id() + 1);
    assert!(s2.borrow().address() == 45.into());
}

#[test]
#[serial]
fn cannot_find_breakpoint_site() {
    let proc = Process::launch(LOOP_ASSIGN_PATH.as_ref(), true, None).unwrap();

    assert!(
        proc.breakpoint_sites()
            .borrow()
            .get_by_address(44.into())
            .is_err()
    );
    assert!(proc.breakpoint_sites().borrow().get_by_id(44).is_err());
}

#[test]
#[serial]
fn breakpoint_sites_list_size() {
    let proc = Process::launch(LOOP_ASSIGN_PATH.as_ref(), true, None).unwrap();
    assert!(proc.breakpoint_sites().borrow().empty());
    assert!(proc.breakpoint_sites().borrow().size() == 0);

    let _ = proc.create_breakpoint_site(42.into(), false, false);
    assert!(!proc.breakpoint_sites().borrow().empty());
    assert!(proc.breakpoint_sites().borrow().size() == 1);

    let _ = proc.create_breakpoint_site(43.into(), false, false);
    assert!(!proc.breakpoint_sites().borrow().empty());
    assert!(proc.breakpoint_sites().borrow().size() == 2);
}

#[test]
#[serial]
fn iterate_breakpoint_sites() {
    let proc = Process::launch(LOOP_ASSIGN_PATH.as_ref(), true, None).unwrap();
    let _ = proc.create_breakpoint_site(42.into(), false, false);
    let _ = proc.create_breakpoint_site(43.into(), false, false);
    let _ = proc.create_breakpoint_site(44.into(), false, false);
    let _ = proc.create_breakpoint_site(45.into(), false, false);

    let mut start = 42;
    proc.breakpoint_sites().borrow_mut().for_each_mut(move |s| {
        assert!(s.borrow().at_address(start.into()));
        start += 1;
    });
}

fn get_section_load_bias(path: &Path, file_address: u64) -> io::Result<i64> {
    let output = Command::new("readelf")
        .args(["-WS", path.to_string_lossy().as_ref()])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("readelf failed with status {}", output.status),
        ));
    }

    let re = Regex::new(r"PROGBITS\s+(\w+)\s+(\w+)\s+(\w+)").expect("hard-coded regex is valid");

    for line in output.stdout.lines() {
        let line = line?;
        if let Some(cap) = re.captures(&line) {
            let address = u64::from_str_radix(&cap[1], 16).unwrap();
            let offset = u64::from_str_radix(&cap[2], 16).unwrap();
            let size = u64::from_str_radix(&cap[3], 16).unwrap();

            if address <= file_address && file_address < address + size {
                return Ok((address - offset) as i64);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Could not find section load bias",
    ))
}

fn get_entry_point_offset(path: &Path) -> io::Result<i64> {
    let data = std::fs::read(path).unwrap();
    let elf = ElfBytes::<AnyEndian>::minimal_parse(data.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let entry_address = elf.ehdr.e_entry;
    let load_bias = get_section_load_bias(path, entry_address)?;
    Ok(entry_address as i64 - load_bias)
}

fn get_load_address(pid: Pid, offset: i64) -> io::Result<VirtualAddress> {
    let maps_path: PathBuf = ["/proc", &pid.to_string(), "maps"].iter().collect();
    let file = File::open(&maps_path)?;
    let reader = BufReader::new(file);
    let re = Regex::new(r"^(\w+)-\w+\s+..(.).\s+(\w+)").expect("hard-coded regex is valid");

    for line in reader.lines() {
        let line = line?;
        if let Some(caps) = re.captures(&line)
            && &caps[2] == "x"
        {
            let low_range = u64::from_str_radix(&caps[1], 16).unwrap();
            let file_offset = i64::from_str_radix(&caps[3], 16).unwrap();
            let load_addr = offset - file_offset + low_range as i64;
            return Ok(VirtualAddress::from(load_addr as u64));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Could not find load address",
    ))
}

#[test]
#[serial]
fn breakpoint_on_address() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let proc =
        Process::launch(HELLO_SDB_PATH.as_ref(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();
    let offset = get_entry_point_offset(HELLO_SDB_PATH.as_ref()).unwrap();
    let load_address = get_load_address(proc.pid(), offset).unwrap();
    proc.create_breakpoint_site(load_address, false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    let reason = proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert_eq!(ProcessState::Stopped, reason.reason);
    assert_eq!(Signal::SIGTRAP as i32, reason.info);
    assert_eq!(load_address, proc.get_pc(None));

    proc.resume(None).unwrap();
    let reason = proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert_eq!(ProcessState::Exited, reason.reason);
    assert_eq!(0, reason.info);

    let data = channel.read().unwrap();
    assert_eq!("Hello, sdb!\n", String::from_utf8(data).unwrap());
}

#[test]
#[serial]
fn remove_breakpoint_sites() {
    let proc = Process::launch(LOOP_ASSIGN_PATH.as_ref(), true, None).unwrap();
    let site = proc.create_breakpoint_site(42.into(), false, false);
    let _ = proc.create_breakpoint_site(43.into(), false, false);
    assert_eq!(2, proc.breakpoint_sites().borrow().size());
    let id = site.unwrap().upgrade().unwrap().borrow().id();
    proc.breakpoint_sites()
        .borrow_mut()
        .remove_by_id(id)
        .unwrap();
    proc.breakpoint_sites()
        .borrow_mut()
        .remove_by_address(43.into())
        .unwrap();
    assert!(proc.breakpoint_sites().borrow().empty());
}

#[test]
#[serial]
fn read_and_write_memory() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let proc = Process::launch(MEMORY_PATH.as_ref(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    let a_pointer: u64 = from_bytes(&channel.read().unwrap());
    let data_vec = proc.read_memory(a_pointer.into(), 8).unwrap();
    let data: u64 = from_bytes(&data_vec);
    assert_eq!(0xcafecafe, data);

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    let b_pointer: u64 = from_bytes(&channel.read().unwrap());
    proc.write_memory(b_pointer.into(), "Hello, sdb!".as_bytes())
        .unwrap();

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    let read = String::from_utf8(channel.read().unwrap()).unwrap();
    assert_eq!("Hello, sdb!", read);
}

#[test]
#[serial]
fn hardware_breapoint_evade_memory_checksum() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let proc = Process::launch(
        ANTI_DEBUGGER_PATH.as_ref(),
        true,
        Some(channel.get_write_fd()),
    )
    .unwrap();
    channel.close_write();

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    let func = VirtualAddress::from(from_bytes::<u64>(&channel.read().unwrap()));
    let soft = proc.create_breakpoint_site(func, false, false).unwrap();
    soft.upgrade().unwrap().borrow_mut().enable().unwrap();

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    assert_eq!(
        String::from_utf8(channel.read().unwrap()).unwrap(),
        "Putting pepperoni on pizza...\n"
    );
    let soft_id = soft.upgrade().unwrap().borrow().id();
    proc.breakpoint_sites()
        .borrow_mut()
        .remove_by_id(soft_id)
        .unwrap();
    let hard = proc.create_breakpoint_site(func, true, false).unwrap();
    hard.upgrade().unwrap().borrow_mut().enable().unwrap();

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    assert_eq!(func, proc.get_pc(None));

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    assert_eq!(
        String::from_utf8(channel.read().unwrap()).unwrap(),
        "Putting pineapple on pizza...\n"
    );
}

#[test]
#[serial]
fn watchpoint_detect_read() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let proc = Process::launch(
        ANTI_DEBUGGER_PATH.as_ref(),
        true,
        Some(channel.get_write_fd()),
    )
    .unwrap();
    channel.close_write();

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    let func = VirtualAddress::from(from_bytes::<u64>(&channel.read().unwrap()));
    let watch = proc
        .create_watchpoint(func, StoppointMode::ReadWrite, 1)
        .unwrap();
    watch.upgrade().unwrap().borrow_mut().enable().unwrap();

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    proc.step_instruction(None).unwrap();
    let soft = proc.create_breakpoint_site(func, false, false).unwrap();
    soft.upgrade().unwrap().borrow_mut().enable().unwrap();

    proc.resume(None).unwrap();
    let reason = proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    assert_eq!(Signal::SIGTRAP as i32, reason.info);

    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    assert_eq!(
        String::from_utf8(channel.read().unwrap()).unwrap(),
        "Putting pineapple on pizza...\n"
    );
}

#[test]
#[serial]
fn syscall_mapping() {
    assert_eq!("read", syscall_id_to_name(0).unwrap());
    assert_eq!(0, syscall_name_to_id("read").unwrap());
    assert_eq!("kill", syscall_id_to_name(62).unwrap());
    assert_eq!(62, syscall_name_to_id("kill").unwrap());
}

#[test]
#[serial]
fn syscall_catchpoint() {
    let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
    let fd = f.as_raw_fd();
    let proc = Process::launch(ANTI_DEBUGGER_PATH.as_ref(), true, Some(fd)).unwrap();
    let write_syscall = syscall_name_to_id("write").unwrap();
    let policy = SyscallCatchPolicy::Some(vec![write_syscall as i32]);
    proc.set_syscall_catch_policy(policy);

    proc.resume(None).unwrap();
    let reason = proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    assert_eq!(ProcessState::Stopped, reason.reason);
    assert_eq!(SIGTRAP as i32, reason.info);
    assert_eq!(Some(TrapType::Syscall), reason.trap_reason);
    assert_eq!(write_syscall as u16, reason.syscall_info.unwrap().id);
    assert!(matches!(
        reason.syscall_info.unwrap().data,
        SyscallData::Args(_)
    ));

    proc.resume(None).unwrap();
    let reason = proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    assert_eq!(ProcessState::Stopped, reason.reason);
    assert_eq!(SIGTRAP as i32, reason.info);
    assert_eq!(Some(TrapType::Syscall), reason.trap_reason);
    assert_eq!(write_syscall as u16, reason.syscall_info.unwrap().id);
    assert!(matches!(
        reason.syscall_info.unwrap().data,
        SyscallData::Ret(_)
    ));
}

#[test]
#[serial]
fn elf_parser() {
    let path = HELLO_SDB_PATH.as_ref();
    let elf = Elf::new(path).unwrap();
    let entry = elf.get_header().0.e_entry;
    let sym = elf
        .get_symbol_at_file_address(FileAddress::new(&elf, entry))
        .unwrap();
    let name = elf.get_string(sym.0.st_name as usize);
    assert_eq!("_start", name);

    let syms = elf.get_symbols_by_name("_start");
    let name = elf.get_string(syms[0].0.st_name as usize);
    assert_eq!("_start", name);
}

#[test]
#[serial]
fn correct_dwarf_language() {
    let path = HELLO_SDB_PATH.as_ref();
    let elf = Elf::new(path).unwrap();
    let dwarf = elf.get_dwarf();
    let compile_units = dwarf.compile_units();
    assert_eq!(1, compile_units.len());
    let cu = &compile_units[0];
    let lang = cu
        .root()
        .index(DW_AT_language.0 as u64)
        .unwrap()
        .as_int()
        .unwrap();
    assert_eq!(DW_LANG_C_plus_plus.0 as u64, lang);
}

#[test]
#[serial]
fn iterate_dwarf() {
    let path = HELLO_SDB_PATH.as_ref();
    let elf = Elf::new(path).unwrap();
    let dwarf = elf.get_dwarf();
    let compile_units = dwarf.compile_units();
    assert_eq!(1, compile_units.len());
    let cu = &compile_units[0];
    let count = cu
        .root()
        .children()
        .filter(|d| {
            assert!(d.as_ref().abbrev_entry().code != 0);
            true
        })
        .count();
    assert!(count > 0);
}

#[test]
#[serial]
fn find_main() {
    let path = MULTI_CU_PATH.as_ref();
    let elf = Elf::new(path).unwrap();
    let dwarf = elf.get_dwarf();
    let found = dwarf.compile_units().iter().any(|cu| {
        cu.root().children().any(|d| {
            let die = d.as_ref();
            die.abbrev_entry().tag as u16 == DW_TAG_subprogram.0
                && die.contains(DW_AT_name.0 as u64)
                && die.index(DW_AT_name.0 as u64).unwrap().as_string().unwrap() == "main"
        })
    });
    assert!(found);
}

#[test]
#[serial]
fn range_list() {
    let path = HELLO_SDB_PATH.as_ref();
    let elf = Elf::new(path).unwrap();
    let dwarf = elf.get_dwarf();
    let compile_units = dwarf.compile_units();
    assert_eq!(1, compile_units.len());
    let cu = &compile_units[0];
    let range_data: Vec<u64> = vec![
        0x12341234, 0x12341236, !0, 0x32, 0x12341234, 0x12341236, 0x0, 0x0,
    ];
    let bytes = Bytes::from_iter(range_data.iter().map(|&x| x.to_ne_bytes()).flatten());
    let list = CompileUnitRangeList::new(cu, &bytes, FileAddress::new(&elf, 0));
    let mut it = list.clone().into_iter();
    let e1 = it.next().unwrap();
    assert_eq!(e1.low.addr(), 0x12341234);
    assert_eq!(e1.high.addr(), 0x12341236);
    assert!(e1.contains(&FileAddress::new(&elf, 0x12341234)));
    assert!(e1.contains(&FileAddress::new(&elf, 0x12341235)));
    assert!(!e1.contains(&FileAddress::new(&elf, 0x12341236)));

    let e2 = it.next().unwrap();
    assert_eq!(e2.low.addr(), 0x12341266);
    assert_eq!(e2.high.addr(), 0x12341268);
    assert!(e2.contains(&FileAddress::new(&elf, 0x12341266)));
    assert!(e2.contains(&FileAddress::new(&elf, 0x12341267)));
    assert!(!e2.contains(&FileAddress::new(&elf, 0x12341268)));

    assert!(matches!(it.next(), None));

    assert!(list.contains(&FileAddress::new(&elf, 0x12341234)));
    assert!(list.contains(&FileAddress::new(&elf, 0x12341235)));
    assert!(!list.contains(&FileAddress::new(&elf, 0x12341236)));
    assert!(list.contains(&FileAddress::new(&elf, 0x12341266)));
    assert!(list.contains(&FileAddress::new(&elf, 0x12341267)));
    assert!(!list.contains(&FileAddress::new(&elf, 0x12341268)));
}

#[test]
#[serial]
fn line_table() {
    let path = HELLO_SDB_PATH.as_ref();
    let elf = Elf::new(path).unwrap();
    let dwarf = elf.get_dwarf();
    let compile_units = dwarf.compile_units();
    assert_eq!(1, compile_units.len());
    let cu = &compile_units[0];
    let mut it = cu.lines().iter().unwrap();
    assert_eq!(it.get_current().line, 2);
    assert_eq!(
        it.get_current()
            .file_entry
            .as_ref()
            .unwrap()
            .path
            .file_name()
            .unwrap(),
        "hello_sdb.cpp"
    );
    it.step().unwrap();
    assert_eq!(it.get_current().line, 3);
    it.step().unwrap();
    assert_eq!(it.get_current().line, 4);
    it.step().unwrap();
    assert!(it.get_current().end_sequence);
    it.step().unwrap();
    assert!(it.is_end());
}

#[test]
#[serial]
fn source_level_breakpoint() {
    let dev_null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    let target = Target::launch(OVERLOADED_PATH.as_ref(), Some(dev_null.as_raw_fd())).unwrap();
    let proc = target.get_process();
    target
        .create_line_breakpoint(Path::new("overloaded.cpp"), 17, false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    let entry = target.line_entry_at_pc(None).unwrap();
    assert_eq!(
        entry
            .get_current()
            .file_entry
            .as_ref()
            .unwrap()
            .path
            .file_name()
            .unwrap(),
        "overloaded.cpp"
    );
    assert_eq!(entry.get_current().line, 17);

    let bkpt = target
        .create_function_breakpoint("print_type", false, false)
        .unwrap();
    let bkpt = bkpt.upgrade().unwrap();
    bkpt.borrow_mut().enable().unwrap();
    let mut lowest_bkpt: Option<Rc<RefCell<dyn StoppointTrait>>> = None;
    for site in bkpt.borrow().breakpoint_sites().iter() {
        if lowest_bkpt.is_none()
            || site.borrow().address().addr()
                < lowest_bkpt.as_ref().unwrap().borrow().address().addr()
        {
            lowest_bkpt = Some(site.clone());
        }
    }
    lowest_bkpt.unwrap().borrow_mut().disable().unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert_eq!(target.line_entry_at_pc(None).unwrap().get_current().line, 9);
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert_eq!(
        target.line_entry_at_pc(None).unwrap().get_current().line,
        13
    );
    proc.resume(None).unwrap();
    let reason = proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert_eq!(reason.reason, ProcessState::Exited);
}

#[test]
#[serial]
fn source_level_stepping() {
    let dev_null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    let file_name = STEP_PATH.file_stem().unwrap().to_str().unwrap();
    let target = Target::launch(STEP_PATH.as_ref(), Some(dev_null.as_raw_fd())).unwrap();
    let proc = target.get_process();
    target
        .create_function_breakpoint("main", false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    let mut pc = proc.get_pc(None);
    assert_eq!(
        target.function_name_at_address(pc).unwrap(),
        format!("{file_name}`main")
    );
    target.step_over(None).unwrap();
    let mut new_pc = proc.get_pc(None);
    assert_ne!(new_pc, pc);
    assert_eq!(
        target.function_name_at_address(pc).unwrap(),
        format!("{file_name}`main")
    );
    target.step_in(None).unwrap();
    pc = proc.get_pc(None);
    assert_eq!(
        target.function_name_at_address(pc).unwrap(),
        format!("{file_name}`find_happiness")
    );
    assert_eq!(target.get_stack(None).borrow().inline_height(), 2);
    target.step_in(None).unwrap();
    new_pc = proc.get_pc(None);
    assert_eq!(new_pc, pc);
    assert_eq!(target.get_stack(None).borrow().inline_height(), 1);
    target.step_out(None).unwrap();
    new_pc = proc.get_pc(None);
    assert_ne!(new_pc, pc);
    assert_eq!(
        target.function_name_at_address(pc).unwrap(),
        format!("{file_name}`find_happiness")
    );
    target.step_out(None).unwrap();
    pc = proc.get_pc(None);
    assert_eq!(
        target.function_name_at_address(pc).unwrap(),
        format!("{file_name}`main")
    );
}

#[test]
#[serial]
fn stack_unwinding() {
    let target = Target::launch(STEP_PATH.as_ref(), None).unwrap();
    let proc = target.get_process();
    target
        .create_function_breakpoint("scratch_ears", false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    target.step_in(None).unwrap();
    target.step_in(None).unwrap();
    let stack = target.get_stack(None);
    let stack = stack.borrow();
    let frames = stack.frames();
    let expected_names = vec!["scratch_ears", "pet_cat", "find_happiness", "main"];
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(frame.func_die.name().unwrap().unwrap(), expected_names[i]);
    }
}

#[test]
#[serial]
fn shared_library_tracing_works() {
    let dev_null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    append_ld_dir("resource/bin");
    let target = Target::launch(MARSHMALLOW_PATH.as_ref(), Some(dev_null.as_raw_fd())).unwrap();
    let proc = target.get_process();

    target
        .create_function_breakpoint("libmeow_client_is_cute", false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    assert_eq!(target.get_stack(None).borrow().frames().len(), 2);
    assert_eq!(
        target.get_stack(None).borrow().frames()[0]
            .func_die
            .name()
            .unwrap()
            .unwrap(),
        "libmeow_client_is_cute"
    );
    assert_eq!(
        target.get_stack(None).borrow().frames()[1]
            .func_die
            .name()
            .unwrap()
            .unwrap(),
        "main"
    );
    assert_eq!(
        target
            .get_pc_file_address(None)
            .rc_elf_file()
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
        "libmeow.so"
    );
}

#[test]
#[serial]
fn multi_threading() {
    let dev_null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    let target = Target::launch(MULTI_THREAD_PATH.as_ref(), Some(dev_null.as_raw_fd())).unwrap();
    let proc = target.get_process();

    target
        .create_function_breakpoint("say_hi", false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();

    let mut tids = HashSet::new();
    loop {
        proc.resume_all_threads().unwrap();
        proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

        for (tid, thread) in proc.thread_states().borrow().iter() {
            if thread.borrow().reason.reason == ProcessState::Stopped && *tid != proc.pid() {
                tids.insert(*tid);
            }
        }

        if tids.len() >= 10 {
            break;
        }
    }

    assert_eq!(tids.len(), 10);

    proc.resume_all_threads().unwrap();
    let reason = proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    assert_eq!(reason.reason, ProcessState::Exited);
}

#[test]
#[serial]
fn read_global_integer_variable() {
    let dev_null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    let target = Target::launch(GLOBAL_VARIABLE_PATH.as_ref(), Some(dev_null.as_raw_fd())).unwrap();
    let proc = target.get_process();

    target
        .create_function_breakpoint("main", false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    let var_die = target
        .get_main_elf()
        .upgrade()
        .unwrap()
        .get_dwarf()
        .find_global_variable("g_int")
        .unwrap()
        .unwrap();
    let var_loc = var_die
        .index(DW_AT_location.0 as u64)
        .unwrap()
        .as_evaluated_location(&proc, &proc.get_registers(None).borrow(), false)
        .unwrap();
    let res = target.read_location_data(&var_loc, 8, None).unwrap();
    let val: u64 = from_bytes(&res);

    assert_eq!(val, 0);

    target.step_over(None).unwrap();
    let res = target.read_location_data(&var_loc, 8, None).unwrap();
    let val: u64 = from_bytes(&res);

    assert_eq!(val, 1);

    target.step_over(None).unwrap();
    let res = target.read_location_data(&var_loc, 8, None).unwrap();
    let val: u64 = from_bytes(&res);

    assert_eq!(val, 42);
}

#[test]
#[serial]
fn dwarf_expressions() {
    let piece_data: Vec<u8> = vec![
        DW_OP_reg16.0 as u8,
        DW_OP_piece.0 as u8,
        4,
        DW_OP_piece.0 as u8,
        8,
        DW_OP_const4u.0 as u8,
        0xff,
        0xff,
        0xff,
        0xff,
        DW_OP_bit_piece.0 as u8,
        5,
        12,
    ];
    let target = Target::launch(STEP_PATH.as_ref(), None).unwrap();
    let proc = target.get_process();
    let data = Bytes::from(piece_data);
    let expr = DwarfExpression::builder()
        .parent(Rc::downgrade(
            &target.get_main_elf().upgrade().unwrap().get_dwarf(),
        ))
        .expr_data(data)
        .in_frame_info(false)
        .build();
    let res = expr
        .eval(&proc, &proc.get_registers(None).borrow(), false)
        .unwrap();
    match res {
        DwarfExpressionResult::Pieces(pieces_result) => {
            let pieces = pieces_result.pieces;
            assert_eq!(pieces.len(), 3);
            assert_eq!(pieces[0].bit_size, 4 * 8);
            assert_eq!(pieces[1].bit_size, 8 * 8);
            assert_eq!(pieces[2].bit_size, 5);
            match &pieces[0].location {
                DwarfExpressionSimpleLocation::Register { reg_num } => {
                    assert_eq!(*reg_num, 16);
                }
                _ => panic!("Expected register location for piece 0"),
            }
            match &pieces[1].location {
                DwarfExpressionSimpleLocation::Empty {} => {
                    // This is expected
                }
                _ => panic!("Expected empty location for piece 1"),
            }
            match &pieces[2].location {
                DwarfExpressionSimpleLocation::Address { address } => {
                    assert_eq!(address.addr(), 0xffffffff);
                }
                _ => panic!("Expected address location for piece 2"),
            }
            assert_eq!(pieces[0].offset, 0);
            assert_eq!(pieces[1].offset, 0);
            assert_eq!(pieces[2].offset, 12);
        }
        _ => panic!("Expected pieces result from DWARF expression"),
    }
}

#[test]
#[serial]
fn global_variables() {
    let target = Target::launch(GLOBAL_VARIABLE_PATH.as_ref(), None).unwrap();
    let proc = target.get_process();

    target
        .create_function_breakpoint("main", false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    let name = target
        .resolve_indirect_name("sy.pets[0].name", &target.get_pc_file_address(None))
        .unwrap();
    let name_vis = name.visualize(&target.get_process(), 0).unwrap();
    assert_eq!(name_vis, "\"Marshmallow\"");

    let cats = target
        .resolve_indirect_name("cats[1].age", &target.get_pc_file_address(None))
        .unwrap();
    let cats_vis = cats.visualize(&target.get_process(), 0).unwrap();
    assert_eq!(cats_vis, "8");
}

#[test]
#[serial]
fn local_variables() {
    let dev_null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    let target = Target::launch(BLOCKS_PATH.as_ref(), Some(dev_null.as_raw_fd())).unwrap();
    let proc = target.get_process();

    target
        .create_function_breakpoint("main", false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();
    target.step_over(None).unwrap();

    let var_data = target
        .resolve_indirect_name("i", &target.get_pc_file_address(None))
        .unwrap();
    let val: u32 = from_bytes(&var_data.data_ptr());
    assert_eq!(val, 1);

    target.step_over(None).unwrap();
    target.step_over(None).unwrap();

    let var_data = target
        .resolve_indirect_name("i", &target.get_pc_file_address(None))
        .unwrap();
    let val: u32 = from_bytes(&var_data.data_ptr());
    assert_eq!(val, 2);

    target.step_over(None).unwrap();
    target.step_over(None).unwrap();

    let var_data = target
        .resolve_indirect_name("i", &target.get_pc_file_address(None))
        .unwrap();
    let val: u32 = from_bytes(&var_data.data_ptr());
    assert_eq!(val, 3);
}

#[test]
#[serial]
fn member_pointers() {
    let target = Target::launch(MEMBER_POINTER_PATH.as_ref(), None).unwrap();
    let proc = target.get_process();
    target
        .create_line_breakpoint(Path::new("member_pointer.cpp"), 10, false, false)
        .unwrap()
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume(None).unwrap();
    proc.wait_on_signal(Pid::from_raw(-1)).unwrap();

    let data_ptr = target
        .resolve_indirect_name("data_ptr", &target.get_pc_file_address(None))
        .unwrap();
    let data_vis = data_ptr.visualize(&proc, 0).unwrap();
    assert_eq!(data_vis, "0x0");

    let func_ptr = target
        .resolve_indirect_name("func_ptr", &target.get_pc_file_address(None))
        .unwrap();
    let func_vis = func_ptr.visualize(&proc, 0).unwrap();
    assert_ne!(func_vis, "0x0");
}
