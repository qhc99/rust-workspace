#![cfg(test)]

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
};

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

#[test]
fn process_attach_success() {
    let status = Command::new("cargo")
        .args(&["build"])
        .current_dir("resource")
        .status()
        .unwrap();
    let target = Process::launch(Path::new("../target/debug/loop_assign"), false).unwrap();
    let proc = Process::attach(target.pid()).unwrap();
    assert!(get_process_state(target.pid()) == "t");
}

#[test]
fn process_attach_invalid_pid() {
    assert!(Process::attach(Pid::from_raw(0)).is_err());
}
