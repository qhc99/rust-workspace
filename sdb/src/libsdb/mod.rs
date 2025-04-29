#![cfg(target_os = "linux")]
#![allow(dead_code)]

use indoc::indoc;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use process::{Process, ProcessState, StopReason};
use registers::F80;
use sdb_error::SdbError;
use std::cell::RefCell;
use std::path::Path;
use std::{ffi::CString, rc::Rc};

mod utils;

pub use utils::ResultLogExt;
pub mod bit;
pub mod pipe;
pub mod process;
pub mod register_info;
pub mod registers;
pub mod sdb_error;
pub mod types;

/// Not async-signal-safe
/// https://man7.org/linux/man-pages/man7/signal-safety.7.html
pub fn attach(args: &[&str]) -> Result<Rc<RefCell<Process>>, SdbError> {
    if args.len() == 3 && args[1] == "-p" {
        let pid = Pid::from_raw(args[2].parse().unwrap());
        return Process::attach(pid);
    } else {
        let program_path = CString::new(args[1]).unwrap();
        return Process::launch(Path::new(program_path.to_str().unwrap()), true, None);
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
    } else if cmd.starts_with("help") {
        print_help(&args);
    } else if cmd.starts_with("register") {
        handle_register_command(process, &args);
    } else {
        log::error!("Unknown command");
    }
    Ok(())
}

fn handle_register_command(process: &Rc<RefCell<Process>>, args: &[&str]) {
    if args.len() < 2 {
        print_help(&["help", "register"]);
        return;
    }

    if args[1].starts_with("read") {
        handle_register_read(process, args);
    } else if args[1].starts_with("write") {
        handle_register_write(process, args);
    } else {
        print_help(&["help", "register"]);
    }
}

fn handle_register_read(process: &Rc<RefCell<Process>>, args: &[&str]) {}

use std::fmt::{self, Write};

trait AutoFormat {
    fn auto_format(&self) -> String;
}

macro_rules! impl_float_auto_format {
    ($($t:ty),*) => {$(
        impl AutoFormat for $t {
            fn auto_format(&self) -> String { format!("{}", self) }
        }
    )*};
}
impl_float_auto_format!(f32, f64, F80);

macro_rules! impl_int_auto_format {
    ($($t:ty),*) => {$(
        impl AutoFormat for $t {
            fn auto_format(&self) -> String {
                // width = bytes * 2  + "0x"
                let width = std::mem::size_of::<$t>() * 2 + 2;
                format!("{:#0width$x}", *self, width = width)
            }
        }
    )*};
}
impl_int_auto_format!(
    u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, usize, isize
);

impl<T: fmt::LowerHex + Copy> AutoFormat for [T] {
    fn auto_format(&self) -> String {
        let mut out = String::with_capacity(self.len() * 6 + 2);
        out.push('[');
        for (i, v) in self.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            write!(out, "{:#04x}", v).unwrap();
        }
        out.push(']');
        out
    }
}
impl<T: fmt::LowerHex + Copy> AutoFormat for Vec<T> {
    fn auto_format(&self) -> String {
        self.as_slice().auto_format()
    }
}

fn handle_register_write(process: &Rc<RefCell<Process>>, args: &[&str]) {}

fn print_help(args: &[&str]) {
    if args.len() == 1 {
        log::error!(indoc! {"
            Available commands:
            continue - Resume the process
            register - Commands for operating on registers
        "
        })
    } else if args[1].starts_with("register") {
        log::error!(indoc! {"
            Available commands:
            read
            read <register>
            read all
            write <register> <value>
        "})
    }
}
