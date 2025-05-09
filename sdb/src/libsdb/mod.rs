#![cfg(target_os = "linux")]
#![allow(dead_code)]

use breakpoint_site::IdType;
use indoc::indoc;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use parse::parse_register_value;
use process::{Process, ProcessExt, ProcessState, StopReason};
use register_info::{GRegisterInfos, RegisterType, register_info_by_name};
use sdb_error::SdbError;
use std::cell::RefCell;
use std::path::Path;
use std::{ffi::CString, rc::Rc};
use traits::StoppointTrait;
use types::VirtualAddress;

mod breakpoint_site;
mod parse;
mod stoppoint_collection;
mod utils;

pub mod traits;
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
        let proc = Process::launch(Path::new(program_path.to_str().unwrap()), true, None)?;
        let pid = proc.borrow().pid();
        println!("Launched process with PID {pid}");
        return Ok(proc);
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
            let addr = process.borrow().get_pc();
            format!("{msg_start} stopped with signal {sig_str} at {:#x}", addr)
        }
        ProcessState::Running => {
            eprintln!("Incorrect state");
            String::new()
        }
    };
    println!("{msg}");
}

pub fn handle_command(process: &Rc<RefCell<Process>>, line: &str) -> Result<(), SdbError> {
    let args: Vec<&str> = line.split(" ").filter(|s| !s.is_empty()).collect();
    let cmd = args[0];
    if cmd == "continue" {
        process.borrow().resume()?;
        let reason = process.borrow().wait_on_signal()?;
        print_stop_reason(process, reason);
    } else if cmd == "help" {
        print_help(&args);
    } else if cmd == "register" {
        handle_register_command(process, &args);
    } else if cmd == "breakpoint" {
        handle_breakpoint_command(process, &args)?;
    } else if cmd == "step" {
        let reason = process.borrow().step_instruction()?;
        print_stop_reason(process, reason);
    } else {
        eprintln!("Unknown command");
    }
    Ok(())
}

fn handle_breakpoint_command(
    process: &Rc<RefCell<Process>>,
    args: &[&str],
) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "register"]);
        return Ok(());
    }

    let command = args[1];
    if command == "list" {
        if process.borrow().breakpoint_sites().borrow().empty() {
            println!("No breakpoints set");
        } else {
            println!("Current breakpoints:");
            process.borrow().breakpoint_sites().borrow().for_each(|s| {
                let id = s.borrow().id();
                let address = s.borrow().address().get_addr();
                let status = if s.borrow().is_enabled() {
                    "enabled"
                } else {
                    "disabled"
                };
                let msg = format!("{id}: address={address:#x}, {status}");
                println!("{msg}");
            });
        }
        return Ok(());
    }

    if args.len() < 3 {
        print_help(&["help", "breakpoint"]);
        return Ok(());
    }

    if command == "set" {
        let address = u64::from_str_radix(args[2].strip_prefix("0x").unwrap_or(args[2]), 16);
        if address.is_err() {
            eprintln!("Breakpoint command expects address in hexadecimal, prefixed with '0x'");
            return Ok(());
        }
        let bs = process.create_breakpoint_site(VirtualAddress::from(address.unwrap()))?;
        bs.borrow_mut().enable()?;
        return Ok(());
    }

    let id = IdType::from_str_radix(args[2].strip_prefix("0x").unwrap_or(args[2]), 16)
        .map_err(|_| SdbError::new_err("Command expects breakpoint id"))?;
    if command == "enable" {
        process
            .borrow()
            .breakpoint_sites()
            .borrow()
            .get_by_id(id)?
            .borrow_mut()
            .enable()?;
    } else if command == "disable" {
        process
            .borrow()
            .breakpoint_sites()
            .borrow()
            .get_by_id(id)?
            .borrow_mut()
            .disable()?;
    } else if command == "delete" {
        process
            .borrow()
            .breakpoint_sites()
            .borrow_mut()
            .remove_by_id(id)?;
    }
    return Ok(());
}

fn handle_register_command(process: &Rc<RefCell<Process>>, args: &[&str]) {
    if args.len() < 2 {
        print_help(&["help", "register"]);
        return;
    }

    if args[1] == "read" {
        handle_register_read(process, args);
    } else if args[1] == "write" {
        handle_register_write(process, args);
    } else {
        print_help(&["help", "register"]);
    }
}

fn handle_register_read(process: &Rc<RefCell<Process>>, args: &[&str]) {
    if args.len() == 2 || (args.len() == 3 && args[2] == "all") {
        for info in GRegisterInfos {
            let should_print =
                (args.len() == 3 || info.type_ == RegisterType::Gpr) && info.name != "orig_rax";
            if !should_print {
                continue;
            }
            let value = process.borrow().get_registers().borrow().read(info);
            println!("{}:\t{}", info.name, value.unwrap());
        }
    } else if args.len() == 3 {
        let info_res = register_info_by_name(args[2]);
        match info_res {
            Ok(info) => {
                let value = process.borrow().get_registers().borrow().read(&info);
                println!("{}:\t{}", info.name, value.unwrap());
            }
            Err(_) => {
                eprintln!("No such register")
            }
        }
    } else {
        print_help(&["help", "register"]);
    }
}

fn handle_register_write(process: &Rc<RefCell<Process>>, args: &[&str]) {
    if args.len() != 4 {
        print_help(&["help", "register"]);
        return;
    }
    if let Err(e) = (|| -> Result<(), SdbError> {
        let info = register_info_by_name(args[2])?;
        let value = parse_register_value(&info, args[3])?;
        process
            .borrow()
            .get_registers()
            .borrow_mut()
            .write(&info, value)?;
        Ok(())
    })() {
        eprintln!("{e}");
    }
}

fn print_help(args: &[&str]) {
    if args.len() == 1 {
        eprintln!(indoc! {"
            Available commands:
            breakpoint - Commands for operating on breakpoints
            continue - Resume the process
            register - Commands for operating on registers
            step - Step over a single instruction
        "
        });
    } else if args[1] == "register" {
        eprintln!(indoc! {"
            Available commands:
            read
            read <register>
            read all
            write <register> <value>
        "});
    } else if args[1] == "breakpoint" {
        eprintln!(indoc! {"
            Available commands:
            list
            delete <id>
            disable <id>
            enable <id>
            set <address>
        "});
    }
}
