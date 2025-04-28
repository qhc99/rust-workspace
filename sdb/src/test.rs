#![cfg(test)]

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use super::test_utils::BinBuilder;
use libsdb::{pipe::Pipe, process::Process};
use libsdb::{register_info::RegisterId, registers::NightlyF128};
use nix::unistd::Pid;

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
    proc.borrow_mut().resume().ok();
    let status = get_process_state(proc.borrow().pid());
    assert!(status == "R" || status == "S");

    let target = super::Process::launch(bin.target_path(), false, None).unwrap();
    let proc = Process::attach(target.borrow().pid()).unwrap();
    proc.borrow_mut().resume().ok();
    let status = get_process_state(proc.borrow().pid());
    assert!(status == "R" || status == "S");
}

#[test]
fn process_resume_terminated() {
    let bin = BinBuilder::rustc("resource", "just_exit.rs");
    let proc = super::Process::launch(bin.target_path(), true, None).unwrap();
    proc.borrow_mut().resume().ok();
    proc.borrow_mut().wait_on_signal().ok();
    assert!(proc.borrow_mut().resume().is_err());
}

#[test]
fn write_registers() {
    let close_on_exec = false;
    let mut channel = Pipe::new(close_on_exec).unwrap();
    let target = BinBuilder::asm("resource", "reg_write.s");
    let proc = Process::launch(target.target_path(), true, Some(channel.get_write_fd())).unwrap();
    channel.close_write();
    proc.borrow_mut().resume().unwrap();
    proc.borrow_mut().wait_on_signal().unwrap();

    {
        proc.borrow()
            .get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::rsi, 0xcafecafe_u64)
            .unwrap();

        proc.borrow_mut().resume().unwrap();
        proc.borrow_mut().wait_on_signal().unwrap();

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

        proc.borrow_mut().resume().unwrap();
        proc.borrow_mut().wait_on_signal().unwrap();

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

        proc.borrow_mut().resume().unwrap();
        proc.borrow_mut().wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "42.24");
    }

    {
        proc.borrow()
            .get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::st0, NightlyF128::new(42.24_f128))
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

        proc.borrow_mut().resume().unwrap();
        proc.borrow_mut().wait_on_signal().unwrap();

        let output = channel.read().unwrap();
        let str = String::from_utf8(output).unwrap();
        assert_eq!(str, "42.24");
    }
}
