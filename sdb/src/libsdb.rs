#![cfg(target_os = "linux")]

use std::ffi::CString;

use nix::sys::ptrace::attach as nix_attach;
use nix::sys::ptrace::traceme;
use nix::unistd::ForkResult;
use nix::unistd::Pid;
use nix::unistd::execvp;
use nix::unistd::fork;

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
            // https://man7.org/linux/man-pages/man7/signal-safety.7.html
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
        }
    }
    return pid;
}
