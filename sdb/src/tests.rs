#![cfg(test)]

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader},
    os::fd::AsRawFd,
    path::PathBuf,
};

use super::test_utils::BinBuilder;
use bytes::Bytes;
use gimli::{DW_AT_language, DW_AT_name, DW_LANG_C_plus_plus, DW_TAG_subprogram};
use libsdb::types::VirtualAddress;
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
use libsdb::{dwarf::Dwarf, syscalls::syscall_name_to_id};
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

fn get_process_state(pid: Pid) -> String {
    let pid_num = pid.as_raw();
    let file = File::open(format!("/proc/{pid_num}/stat")).unwrap();
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let idx = line.match_indices(")").into_iter().last().unwrap().0;
    return String::from_utf8_lossy(&line.as_bytes()[idx + 2..idx + 3]).to_string();
}

#[test]
fn process_attach_success() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let target = Process::launch(bin.target_path(), false, None).unwrap();
    let _proc = Process::attach(target.pid()).unwrap();
    assert!(get_process_state(target.pid()) == "t");
}

#[test]
fn process_attach_invalid_pid() {
    assert!(Process::attach(Pid::from_raw(0)).is_err());
}

#[test]
fn process_resume_success() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();
    proc.resume().ok();
    let status = get_process_state(proc.pid());
    assert!(status == "R" || status == "S");

    let target = Process::launch(bin.target_path(), false, None).unwrap();
    let proc = Process::attach(target.pid()).unwrap();
    proc.resume().ok();
    let status = get_process_state(proc.pid());
    assert!(status == "R" || status == "S");
}

#[test]
fn process_resume_terminated() {
    let bin = BinBuilder::rustc("resource", "just_exit.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();
    proc.resume().ok();
    proc.wait_on_signal().ok();
    assert!(proc.resume().is_err());
}

#[test]
fn write_registers() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let target = BinBuilder::asm("resource", "reg_write.s");
    let proc = Process::launch(target.target_path(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();
    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    {
        proc.get_registers()
            .borrow_mut()
            .as_mut()
            .unwrap()
            .write_by_id(RegisterId::rsi, 0xcafecafe_u64)
            .unwrap();

        proc.resume().unwrap();
        proc.wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "0xcafecafe");
    }

    {
        proc.get_registers()
            .borrow_mut()
            .as_mut()
            .unwrap()
            .write_by_id(RegisterId::mm0, 0xba5eba11_u64)
            .unwrap();

        proc.resume().unwrap();
        proc.wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "0xba5eba11")
    }

    {
        proc.get_registers()
            .borrow_mut()
            .as_mut()
            .unwrap()
            .write_by_id(RegisterId::xmm0, 42.24)
            .unwrap();

        proc.resume().unwrap();
        proc.wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "42.24");
    }

    {
        proc.get_registers()
            .borrow_mut()
            .as_mut()
            .unwrap()
            .write_by_id(RegisterId::st0, F80::new(42.24))
            .unwrap();
        proc.get_registers()
            .borrow_mut()
            .as_mut()
            .unwrap()
            .write_by_id(RegisterId::fsw, 0b0011100000000000_u16)
            .unwrap();
        proc.get_registers()
            .borrow_mut()
            .as_mut()
            .unwrap()
            .write_by_id(RegisterId::ftw, 0b0011111111111111_u16)
            .unwrap();

        proc.resume().unwrap();
        proc.wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "42.24");
    }
}

#[test]
fn read_registers() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let target = BinBuilder::asm("resource", "reg_read.s");
    let proc = Process::launch(target.target_path(), true, Some(channel.get_write_fd())).unwrap();
    let regs = proc.get_registers();
    channel.close_write();

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();
    assert!(
        regs.borrow()
            .as_ref()
            .unwrap()
            .read_by_id_as::<u64>(RegisterId::r13)
            .unwrap()
            == 0xcafecafe_u64
    );

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();
    assert!(
        regs.borrow()
            .as_ref()
            .unwrap()
            .read_by_id_as::<u8>(RegisterId::r13b)
            .unwrap()
            == 42
    );

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();
    assert!(
        regs.borrow()
            .as_ref()
            .unwrap()
            .read_by_id_as::<Byte64>(RegisterId::mm0)
            .unwrap()
            == to_byte64(0xba5eba11_u64)
    );

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();
    assert!(
        regs.borrow()
            .as_ref()
            .unwrap()
            .read_by_id_as::<Byte128>(RegisterId::xmm0)
            .unwrap()
            == to_byte128(64.125)
    );

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();
    assert!(
        regs.borrow()
            .as_ref()
            .unwrap()
            .read_by_id_as::<F80>(RegisterId::st0)
            .unwrap()
            == F80::new(64.125)
    );
}

#[test]
fn create_breakpoint_site() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();
    let site = proc.create_breakpoint_site(42.into(), false, false);
    assert_eq!(VirtualAddress::from(42), site.unwrap().borrow().address());
}

#[test]
fn create_breakpoint_site_id_increase() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();
    let site1 = proc
        .create_breakpoint_site(42.into(), false, false)
        .unwrap();
    assert_eq!(VirtualAddress::from(42), site1.borrow().address());

    let site2 = proc
        .create_breakpoint_site(43.into(), false, false)
        .unwrap();
    assert_eq!(site2.borrow().id(), site1.borrow().id() + 1);

    let site3 = proc
        .create_breakpoint_site(44.into(), false, false)
        .unwrap();
    assert_eq!(site3.borrow().id(), site2.borrow().id() + 1);

    let site4 = proc
        .create_breakpoint_site(45.into(), false, false)
        .unwrap();
    assert_eq!(site4.borrow().id(), site3.borrow().id() + 1);
}

#[test]
fn find_breakpoint_sites() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();
    let _ = proc.create_breakpoint_site(42.into(), false, false);
    let _ = proc.create_breakpoint_site(43.into(), false, false);
    let _ = proc.create_breakpoint_site(44.into(), false, false);
    let _ = proc.create_breakpoint_site(45.into(), false, false);

    let s1 = proc
        .breakpoint_sites()
        .borrow()
        .get_by_address(44.into())
        .unwrap();
    assert!(proc.breakpoint_sites().borrow().contain_address(44.into()));
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
fn cannot_find_breakpoint_site() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();

    assert!(
        proc.breakpoint_sites()
            .borrow()
            .get_by_address(44.into())
            .is_err()
    );
    assert!(proc.breakpoint_sites().borrow().get_by_id(44).is_err());
}

#[test]
fn breakpoint_sites_list_size() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();
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
fn iterate_breakpoint_sites() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();
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
        if let Some(caps) = re.captures(&line) {
            if &caps[2] == "x" {
                let low_range = u64::from_str_radix(&caps[1], 16).unwrap();
                let file_offset = i64::from_str_radix(&caps[3], 16).unwrap();
                let load_addr = offset - file_offset + low_range as i64;
                return Ok(VirtualAddress::from(load_addr as u64));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Could not find load address",
    ))
}

#[test]
fn breakpoint_on_address() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let bin = BinBuilder::cpp("resource", &["hello_sdb.cpp"]);
    let proc = Process::launch(bin.target_path(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();
    let offset = get_entry_point_offset(bin.target_path()).unwrap();
    let load_address = get_load_address(proc.pid(), offset).unwrap();
    proc.create_breakpoint_site(load_address, false, false)
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.resume().unwrap();
    let reason = proc.wait_on_signal().unwrap();
    assert_eq!(ProcessState::Stopped, reason.reason);
    assert_eq!(Signal::SIGTRAP as i32, reason.info);
    assert_eq!(load_address, proc.get_pc());

    proc.resume().unwrap();
    let reason = proc.wait_on_signal().unwrap();
    assert_eq!(ProcessState::Exited, reason.reason);
    assert_eq!(0, reason.info);

    let data = channel.read().unwrap();
    assert_eq!("Hello, sdb!\n", String::from_utf8(data).unwrap());
}

#[test]
fn remove_breakpoint_sites() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = Process::launch(bin.target_path(), true, None).unwrap();
    let site = proc.create_breakpoint_site(42.into(), false, false);
    let _ = proc.create_breakpoint_site(43.into(), false, false);
    assert_eq!(2, proc.breakpoint_sites().borrow().size());
    let id = site.unwrap().borrow().id();
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
fn read_and_write_memory() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let bin = BinBuilder::cpp("resource", &["memory.cpp"]);
    let proc = Process::launch(bin.target_path(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();
    let a_pointer: u64 = from_bytes(&channel.read().unwrap());
    let data_vec = proc.read_memory(a_pointer.into(), 8).unwrap();
    let data: u64 = from_bytes(&data_vec);
    assert_eq!(0xcafecafe, data);

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();
    let b_pointer: u64 = from_bytes(&channel.read().unwrap());
    proc.write_memory(b_pointer.into(), "Hello, sdb!".as_bytes())
        .unwrap();

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    let read = String::from_utf8(channel.read().unwrap()).unwrap();
    assert_eq!("Hello, sdb!", read);
}

#[test]
fn hardware_breapoint_evade_memory_checksum() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let bin = BinBuilder::cpp("resource", &["anti_debugger.cpp"]);
    let proc = Process::launch(bin.target_path(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    let func = VirtualAddress::from(from_bytes::<u64>(&channel.read().unwrap()));
    let soft = proc.create_breakpoint_site(func, false, false).unwrap();
    soft.borrow_mut().enable().unwrap();

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    assert_eq!(
        String::from_utf8(channel.read().unwrap()).unwrap(),
        "Putting pepperoni on pizza...\n"
    );
    let soft_id = soft.borrow().id();
    proc.breakpoint_sites()
        .borrow_mut()
        .remove_by_id(soft_id)
        .unwrap();
    let hard = proc.create_breakpoint_site(func, true, false).unwrap();
    hard.borrow_mut().enable().unwrap();

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    assert_eq!(func, proc.get_pc());

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    assert_eq!(
        String::from_utf8(channel.read().unwrap()).unwrap(),
        "Putting pineapple on pizza...\n"
    );
}

#[test]
fn watchpoint_detect_read() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let bin = BinBuilder::cpp("resource", &["anti_debugger.cpp"]);
    let proc = Process::launch(bin.target_path(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    let func = VirtualAddress::from(from_bytes::<u64>(&channel.read().unwrap()));
    let watch = proc
        .create_watchpoint(func, StoppointMode::ReadWrite, 1)
        .unwrap();
    watch.borrow_mut().enable().unwrap();

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    proc.step_instruction().unwrap();
    let soft = proc.create_breakpoint_site(func, false, false).unwrap();
    soft.borrow_mut().enable().unwrap();

    proc.resume().unwrap();
    let reason = proc.wait_on_signal().unwrap();

    assert_eq!(Signal::SIGTRAP as i32, reason.info);

    proc.resume().unwrap();
    proc.wait_on_signal().unwrap();

    assert_eq!(
        String::from_utf8(channel.read().unwrap()).unwrap(),
        "Putting pineapple on pizza...\n"
    );
}

#[test]
fn syscall_mapping() {
    assert_eq!("read", syscall_id_to_name(0).unwrap());
    assert_eq!(0, syscall_name_to_id("read").unwrap());
    assert_eq!("kill", syscall_id_to_name(62).unwrap());
    assert_eq!(62, syscall_name_to_id("kill").unwrap());
}

#[test]
fn syscall_catchpoint() {
    let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
    let fd = f.as_raw_fd();
    let bin = BinBuilder::cpp("resource", &["anti_debugger.cpp"]);

    let proc = Process::launch(bin.target_path(), true, Some(fd)).unwrap();
    let write_syscall = syscall_name_to_id("write").unwrap();
    let policy = SyscallCatchPolicy::Some(vec![write_syscall as i32]);
    proc.set_syscall_catch_policy(policy);

    proc.resume().unwrap();
    let reason = proc.wait_on_signal().unwrap();

    assert_eq!(ProcessState::Stopped, reason.reason);
    assert_eq!(SIGTRAP as i32, reason.info);
    assert_eq!(Some(TrapType::Syscall), reason.trap_reason);
    assert_eq!(write_syscall as u16, reason.syscall_info.unwrap().id);
    assert!(matches!(
        reason.syscall_info.unwrap().data,
        SyscallData::Args(_)
    ));

    proc.resume().unwrap();
    let reason = proc.wait_on_signal().unwrap();

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
fn elf_parser() {
    let bin = BinBuilder::cpp("resource", &["hello_sdb.cpp"]);
    let path = bin.target_path();
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
fn correct_dwarf_language() {
    let bin = BinBuilder::cpp("resource", &["hello_sdb.cpp"]);
    let path = bin.target_path();
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
fn iterate_dwarf() {
    let bin = BinBuilder::cpp("resource", &["hello_sdb.cpp"]);
    let path = bin.target_path();
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
fn find_main() {
    let bin = BinBuilder::cpp("resource", &["multi_cu_main.cpp", "multi_cu_other.cpp"]);
    let path = bin.target_path();
    let elf = Elf::new(path).unwrap();
    let dwarf = Dwarf::new(&elf).unwrap();
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
fn range_list() {
    let bin = BinBuilder::cpp("resource", &["hello_sdb.cpp"]);
    let path = bin.target_path();
    let elf = Elf::new(path).unwrap();
    let dwarf = Dwarf::new(&elf).unwrap();
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
