#![cfg(target_os = "linux")]
#![allow(dead_code)]

use std::cell::RefCell;
use std::path::Path;
use std::{ffi::CString, rc::Rc};

use nix::sys::signal::Signal;
use nix::unistd::Pid;
use process::{Process, ProcessState, StopReason};
use sdb_error::SdbError;
pub use utils::ResultLogExt;

mod bit;
mod pipe;
pub mod process;
mod register_info;
mod registers;
pub mod sdb_error;
mod types;
mod utils;

/// Not async-signal-safe
/// https://man7.org/linux/man-pages/man7/signal-safety.7.html
pub fn attach(args: &[&str]) -> Result<Rc<RefCell<Process>>, SdbError> {
    if args.len() == 3 && args[1] == "-p" {
        let pid = Pid::from_raw(args[2].parse().unwrap());
        return Process::attach(pid);
    } else {
        let program_path = CString::new(args[1]).unwrap();
        return Process::launch(Path::new(program_path.to_str().unwrap()), true);
    }
}

fn print_stop_reason(process: &Rc<RefCell<Process>>, reason: StopReason) {
    let pid = process.borrow().pid();
    let msg_start = format!("Process {pid}");
    let msg = match reason.reason {
        ProcessState::Exited => {
            let info = reason.info;
            format!("{msg_start} exited with status {info}")
        }
        ProcessState::Terminated => {
            let signal: Signal = reason.info.try_into().unwrap();
            let sig_str = signal.as_str();
            format!("{msg_start} terminated with signal {sig_str}")
        }
        ProcessState::Stopped => {
            let signal: Signal = reason.info.try_into().unwrap();
            let sig_str = signal.as_str();
            format!("{msg_start} stopped with signal {sig_str}")
        }
        ProcessState::Running => {
            log::error!("Incorrect state");
            String::new()
        }
    };
    log::info!("{msg}");
}

pub fn handle_command(process: &Rc<RefCell<Process>>, line: &str) -> Result<(), SdbError> {
    let args: Vec<&str> = line.split(" ").filter(|s| !s.is_empty()).collect();
    let cmd = args[0];
    if cmd.starts_with("continue") {
        process.borrow_mut().resume()?;
        let reason = process.borrow_mut().wait_on_signal()?;
        print_stop_reason(process, reason);
    } else {
        log::error!("Unknown command");
    }
    Ok(())
}
