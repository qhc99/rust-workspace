#![cfg(test)]

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use super::test_utils::RustcBuilder;
use libsdb::process::Process;
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

fn build_target_loop_assign() -> RustcBuilder {
    RustcBuilder::new("resource", "loop_assign.rs")
}

fn build_target_just_exit() -> RustcBuilder {
    RustcBuilder::new("resource", "just_exit.rs")
}

#[test]
fn process_attach_success() {
    let bin = build_target_loop_assign();
    let target = Process::launch(bin.target_path(), false).unwrap();
    let _proc = Process::attach(target.borrow().pid()).unwrap();
    assert!(get_process_state(target.borrow().pid()) == "t");
}

#[test]
fn process_attach_invalid_pid() {
    assert!(Process::attach(Pid::from_raw(0)).is_err());
}

#[test]
fn process_resume_success() {
    let bin = build_target_loop_assign();
    let proc = super::Process::launch(bin.target_path(), true).unwrap();
    proc.borrow_mut().resume().ok();
    let status = get_process_state(proc.borrow().pid());
    assert!(status == "R" || status == "S");

    let target = super::Process::launch(bin.target_path(), false).unwrap();
    let proc = Process::attach(target.borrow().pid()).unwrap();
    proc.borrow_mut().resume().ok();
    let status = get_process_state(proc.borrow().pid());
    assert!(status == "R" || status == "S");
}

#[test]
fn process_resume_terminated() {
    let bin = build_target_just_exit();
    let proc = super::Process::launch(bin.target_path(), true).unwrap();
    proc.borrow_mut().resume().ok();
    proc.borrow().wait_on_signal().ok();
    assert!(proc.borrow_mut().resume().is_err());
}
