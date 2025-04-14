#![cfg(target_os = "linux")]

use std::ffi::CString;

use nix::sys::ptrace::attach as nix_attach;
use nix::sys::ptrace::cont;
use nix::sys::ptrace::traceme;
use nix::sys::wait::{WaitPidFlag, waitpid};
use nix::unistd::ForkResult;
use nix::unistd::Pid;
use nix::unistd::execvp;
use nix::unistd::fork;
use std::process::exit;

pub mod process;
pub mod sdb_error;

/// Not async-signal-safe
/// https://man7.org/linux/man-pages/man7/signal-safety.7.html
pub fn attach(args: &[&str]) -> Pid {
    let mut pid = Pid::from_raw(0);
    if args.len() == 3 && args[1] == "-p" {
        pid = Pid::from_raw(args[2].parse().unwrap());
        if pid <= Pid::from_raw(0) {
            eprintln!("Invalid pid");
            return Pid::from_raw(-1);
        }
        if nix_attach(pid).is_err() {
            eprintln!("Could not attach");
            return Pid::from_raw(-1);
        }
    } else {
        let program_path = CString::new(args[1]).unwrap();
        let fork_res;
        unsafe {
            // unsafe in signal handler context
            fork_res = fork();
        }
        if let Ok(ForkResult::Child) = fork_res {
            if traceme().is_err() {
                eprintln!("Tracing failed");
                return Pid::from_raw(-1);
            }
            if execvp(&program_path, &[&program_path]).is_err() {
                eprintln!("Exec failed");
                return Pid::from_raw(-1);
            }
        } else {
            eprintln!("Fork failed");
        }
    }
    return pid;
}

pub fn resume(pid: Pid) {
    if cont(pid, None).is_err() {
        eprintln!("Couldn't continue");
        exit(-1);
    }
}

pub fn wait_on_signal(pid: Pid) {
    let options = WaitPidFlag::from_bits(0);
    if waitpid(pid, options).is_err() {
        eprintln!("waitpid failed");
        exit(-1);
    }
}

pub fn handle_command(pid: Pid, line: &str) {
    let args: Vec<&str> = line
        .split(" ")
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let cmd = args[0];
    if cmd.starts_with("continue") {
        resume(pid);
        wait_on_signal(pid);
    } else {
        eprintln!("Unknown command");
    }
}
