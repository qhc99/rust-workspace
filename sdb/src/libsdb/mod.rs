#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::path::Path;

use nix::sys::signal::Signal;
use nix::unistd::Pid;
use sdb_error::SdbError;

pub mod process;
pub mod sdb_error;
mod pipe;
mod utils;
use process::{Process, ProcessState, StopReason};
pub use utils::ResultLogExt;

/// Not async-signal-safe
/// https://man7.org/linux/man-pages/man7/signal-safety.7.html
pub fn attach(args: &[&str]) -> Result<Box<Process>, SdbError> {
    if args.len() == 3 && args[1] == "-p" {
        let pid = Pid::from_raw(args[2].parse().unwrap());
        return Process::attach(pid);
    } else {
        let program_path = CString::new(args[1]).unwrap();
        return Process::launch(Path::new(program_path.to_str().unwrap()));
    }
}

fn print_stop_reason(process: &Box<Process>, reason: StopReason) {
    let pid = process.pid();
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

pub fn handle_command(process: &mut Box<Process>, line: &str) -> Result<(), SdbError> {
    let args: Vec<&str> = line
        .split(" ")
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let cmd = args[0];
    if cmd.starts_with("continue") {
        process.resume()?;
        let reason = process.wait_on_signal()?;
        print_stop_reason(process, reason);
    } else {
        log::error!("Unknown command");
    }
    Ok(())
}
