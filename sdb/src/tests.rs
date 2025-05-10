#![cfg(test)]

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use super::libsdb::process::ProcessState;
use super::libsdb::register_info::RegisterId;
use super::libsdb::types::VirtualAddress;
use super::libsdb::{
    bit::{to_byte64, to_byte128},
    pipe::Pipe,
    process::Process,
    registers::F80,
    types::{Byte64, Byte128},
};
use super::libsdb::{process::ProcessExt, traits::StoppointTrait};
use super::test_utils::BinBuilder;
use nix::{sys::signal::Signal, unistd::Pid};
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
    let _proc = Process::attach(target.borrow().pid()).unwrap();
    assert!(get_process_state(target.borrow().pid()) == "t");
}

#[test]
fn process_attach_invalid_pid() {
    assert!(Process::attach(Pid::from_raw(0)).is_err());
}

#[test]
fn process_resume_success() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    proc.borrow().resume().ok();
    let status = get_process_state(proc.borrow().pid());
    assert!(status == "R" || status == "S");

    let target = super::Process::launch(bin.target_path(), false, None).unwrap();
    let proc = Process::attach(target.borrow().pid()).unwrap();
    proc.borrow().resume().ok();
    let status = get_process_state(proc.borrow().pid());
    assert!(status == "R" || status == "S");
}

#[test]
fn process_resume_terminated() {
    let bin = BinBuilder::rustc("resource", "just_exit.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    proc.borrow().resume().ok();
    proc.borrow().wait_on_signal().ok();
    assert!(proc.borrow().resume().is_err());
}

#[test]
fn write_registers() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let target = BinBuilder::asm("resource", "reg_write.s");
    let proc = Process::launch(target.target_path(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();
    proc.borrow().resume().unwrap();
    proc.borrow().wait_on_signal().unwrap();

    {
        proc.borrow()
            .get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::rsi, 0xcafecafe_u64)
            .unwrap();

        proc.borrow().resume().unwrap();
        proc.borrow().wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "0xcafecafe");
    }

    {
        proc.borrow()
            .get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::mm0, 0xba5eba11_u64)
            .unwrap();

        proc.borrow().resume().unwrap();
        proc.borrow().wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "0xba5eba11")
    }

    {
        proc.borrow()
            .get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::xmm0, 42.24)
            .unwrap();

        proc.borrow().resume().unwrap();
        proc.borrow().wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "42.24");
    }

    {
        proc.borrow()
            .get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::st0, F80::new(42.24))
            .unwrap();
        proc.borrow()
            .get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::fsw, 0b0011100000000000_u16)
            .unwrap();
        proc.borrow()
            .get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::ftw, 0b0011111111111111_u16)
            .unwrap();

        proc.borrow().resume().unwrap();
        proc.borrow().wait_on_signal().unwrap();

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
    let regs = proc.borrow().get_registers();
    channel.close_write();

    proc.borrow().resume().unwrap();
    proc.borrow().wait_on_signal().unwrap();
    assert!(regs.borrow().read_by_id_as::<u64>(RegisterId::r13).unwrap() == 0xcafecafe_u64);

    proc.borrow().resume().unwrap();
    proc.borrow().wait_on_signal().unwrap();
    assert!(regs.borrow().read_by_id_as::<u8>(RegisterId::r13b).unwrap() == 42);

    proc.borrow().resume().unwrap();
    proc.borrow().wait_on_signal().unwrap();
    assert!(
        regs.borrow()
            .read_by_id_as::<Byte64>(RegisterId::mm0)
            .unwrap()
            == to_byte64(0xba5eba11_u64)
    );

    proc.borrow().resume().unwrap();
    proc.borrow().wait_on_signal().unwrap();
    assert!(
        regs.borrow()
            .read_by_id_as::<Byte128>(RegisterId::xmm0)
            .unwrap()
            == to_byte128(64.125)
    );

    proc.borrow().resume().unwrap();
    proc.borrow().wait_on_signal().unwrap();
    assert!(regs.borrow().read_by_id_as::<F80>(RegisterId::st0).unwrap() == F80::new(64.125));
}

#[test]
fn create_breakpoint_site() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    let site = proc.create_breakpoint_site(42.into());
    assert_eq!(VirtualAddress::from(42), site.unwrap().borrow().address());
}

#[test]
fn create_breakpoint_site_id_increase() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    let site1 = proc.create_breakpoint_site(42.into());
    assert_eq!(
        VirtualAddress::from(42),
        site1.as_ref().unwrap().borrow().address()
    );

    let site2 = proc.create_breakpoint_site(43.into());
    assert_eq!(
        site2.as_ref().unwrap().borrow().id(),
        site1.as_ref().unwrap().borrow().id() + 1
    );

    let site3 = proc.create_breakpoint_site(44.into());
    assert_eq!(
        site3.as_ref().unwrap().borrow().id(),
        site2.as_ref().unwrap().borrow().id() + 1
    );

    let site4 = proc.create_breakpoint_site(45.into());
    assert_eq!(
        site4.as_ref().unwrap().borrow().id(),
        site3.as_ref().unwrap().borrow().id() + 1
    );
}

#[test]
fn find_breakpoint_sites() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    let _ = proc.create_breakpoint_site(42.into());
    let _ = proc.create_breakpoint_site(43.into());
    let _ = proc.create_breakpoint_site(44.into());
    let _ = proc.create_breakpoint_site(45.into());

    let s1 = proc
        .borrow()
        .breakpoint_sites()
        .borrow()
        .get_by_address(44.into())
        .unwrap();
    assert!(
        proc.borrow()
            .breakpoint_sites()
            .borrow()
            .contain_address(44.into())
    );
    assert!(s1.borrow().address() == 44.into());

    let s2 = proc
        .borrow()
        .breakpoint_sites()
        .borrow()
        .get_by_id(s1.borrow().id() + 1)
        .unwrap();
    assert!(
        proc.borrow()
            .breakpoint_sites()
            .borrow()
            .contain_id(s1.borrow().id() + 1)
    );
    assert!(s2.borrow().id() == s1.borrow().id() + 1);
    assert!(s2.borrow().address() == 45.into());
}

#[test]
fn cannot_find_breakpoint_site() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();

    assert!(
        proc.borrow()
            .breakpoint_sites()
            .borrow()
            .get_by_address(44.into())
            .is_err()
    );
    assert!(
        proc.borrow()
            .breakpoint_sites()
            .borrow()
            .get_by_id(44)
            .is_err()
    );
}

#[test]
fn breakpoint_sites_list_size() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    assert!(proc.borrow().breakpoint_sites().borrow().empty());
    assert!(proc.borrow().breakpoint_sites().borrow().size() == 0);

    let _ = proc.create_breakpoint_site(42.into());
    assert!(!proc.borrow().breakpoint_sites().borrow().empty());
    assert!(proc.borrow().breakpoint_sites().borrow().size() == 1);

    let _ = proc.create_breakpoint_site(43.into());
    assert!(!proc.borrow().breakpoint_sites().borrow().empty());
    assert!(proc.borrow().breakpoint_sites().borrow().size() == 2);
}

#[test]
fn iterate_breakpoint_sites() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    let _ = proc.create_breakpoint_site(42.into());
    let _ = proc.create_breakpoint_site(43.into());
    let _ = proc.create_breakpoint_site(44.into());
    let _ = proc.create_breakpoint_site(45.into());

    let mut start = 42;
    proc.borrow()
        .breakpoint_sites()
        .borrow_mut()
        .for_each_mut(move |s| {
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
    let bin = BinBuilder::cpp("resource", "hello_sdb.cpp");
    let proc = Process::launch(bin.target_path(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();
    let offset = get_entry_point_offset(bin.target_path()).unwrap();
    let load_address = get_load_address(proc.borrow().pid(), offset).unwrap();
    proc.create_breakpoint_site(load_address)
        .unwrap()
        .borrow_mut()
        .enable()
        .unwrap();
    proc.borrow().resume().unwrap();
    let reason = proc.borrow().wait_on_signal().unwrap();
    assert_eq!(ProcessState::Stopped, reason.reason);
    assert_eq!(Signal::SIGTRAP as i32, reason.info);
    assert_eq!(load_address, proc.borrow().get_pc());

    proc.borrow().resume().unwrap();
    let reason = proc.borrow().wait_on_signal().unwrap();
    assert_eq!(ProcessState::Exited, reason.reason);
    assert_eq!(0, reason.info);

    let data = channel.read().unwrap();
    assert_eq!("Hello, sdb!\n", String::from_utf8(data).unwrap());
}

#[test]
fn remove_breakpoint_sites() {
    let bin = BinBuilder::rustc("resource", "loop_assign.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    let site = proc.create_breakpoint_site(42.into());
    let _ = proc.create_breakpoint_site(43.into());
    assert_eq!(2, proc.borrow().breakpoint_sites().borrow().size());
    let id = site.unwrap().borrow().id();
    proc.borrow()
        .breakpoint_sites()
        .borrow_mut()
        .remove_by_id(id)
        .unwrap();
    proc.borrow()
        .breakpoint_sites()
        .borrow_mut()
        .remove_by_address(43.into())
        .unwrap();
    assert!(proc.borrow().breakpoint_sites().borrow().empty());
}
