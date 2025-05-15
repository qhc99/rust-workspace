#![cfg(target_os = "linux")]
#![allow(dead_code)]

use breakpoint_site::IdType;
use disassembler::print_disassembly;
use indoc::indoc;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use parse::{parse_register_value, parse_vector};
use process::{Process, ProcessExt, ProcessState, StopReason};
use register_info::{GRegisterInfos, RegisterType, register_info_by_name};
use sdb_error::SdbError;
use std::cell::{Ref, RefCell};
use std::cmp::min;
use std::path::Path;
use std::{ffi::CString, rc::Rc};
use traits::FromLowerHexStr;
use traits::StoppointTrait;
use types::VirtualAddress;

mod breakpoint_site;
mod disassembler;
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

fn print_stop_reason(process: &Ref<Process>, reason: StopReason) {
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
            let addr = process.get_pc();
            format!("{msg_start} stopped with signal {sig_str} at {:#x}", addr)
        }
        ProcessState::Running => {
            eprintln!("Incorrect state");
            String::new()
        }
    };
    println!("{msg}");
}

pub fn handle_command(owned_process: &Rc<RefCell<Process>>, line: &str) -> Result<(), SdbError> {
    let args: Vec<&str> = line.split(" ").filter(|s| !s.is_empty()).collect();
    let cmd = args[0];
    let process = &owned_process.borrow();
    if cmd == "continue" {
        process.resume()?;
        let reason = process.wait_on_signal()?;
        handle_stop(owned_process, reason)?;
    } else if cmd == "help" {
        print_help(&args);
    } else if cmd == "register" {
        handle_register_command(process, &args);
    } else if cmd == "breakpoint" {
        handle_breakpoint_command(owned_process, &args)?;
    } else if cmd == "step" {
        let reason = process.step_instruction()?;
        handle_stop(owned_process, reason)?;
    } else if cmd == "memory" {
        handle_memory_command(process, &args)?;
    } else if cmd == "disassemble" {
        handle_disassemble_command(owned_process, &args)?;
    } else {
        eprintln!("Unknown command");
    }
    Ok(())
}

fn handle_disassemble_command(
    process: &Rc<RefCell<Process>>,
    args: &[&str],
) -> Result<(), SdbError> {
    let mut address = process.borrow().get_pc();
    let mut n_instructions = 5usize;
    let mut args_iter = args.iter();
    args_iter.next();
    loop {
        match args_iter.next() {
            Some(data) => match *data {
                "-a" => {
                    let opt_addr = args_iter
                        .next()
                        .ok_or(SdbError::new_err("Invalid address format"))?;
                    address = u64::from_lower_hex_radix(opt_addr, 16)?.into();
                }
                "-c" => {
                    let instruction_count = args_iter
                        .next()
                        .ok_or(SdbError::new_err("Invalid instruction count"))?;
                    n_instructions = usize::from_lower_hex(instruction_count)?;
                }
                _ => {
                    print_help(&["help", "disassemble"]);
                    return Ok(());
                }
            },
            None => break,
        }
    }
    print_disassembly(process, address, n_instructions)?;
    Ok(())
}

fn handle_stop(process: &Rc<RefCell<Process>>, reason: StopReason) -> Result<(), SdbError> {
    let ref_process = &process.borrow();
    print_stop_reason(ref_process, reason);
    if reason.reason == ProcessState::Stopped {
        print_disassembly(process, ref_process.get_pc(), 5)?;
    }
    Ok(())
}

fn handle_memory_command(process: &Ref<Process>, args: &[&str]) -> Result<(), SdbError> {
    if args.len() < 3 {
        print_help(&["help", "memory"]);
        return Ok(());
    }
    if args[1] == "read" {
        handle_memory_read_command(process, args)?;
    } else if args[1] == "write" {
        handle_memory_write_command(process, args)?;
    } else {
        print_help(&["help", "memory"]);
    }

    Ok(())
}

fn handle_memory_read_command(process: &Ref<Process>, args: &[&str]) -> Result<(), SdbError> {
    let address = u64::from_lower_hex_radix(args[2], 16)?;
    let mut n_bytes = 32usize;
    if args.len() == 4 {
        let bytes_args = usize::from_lower_hex_radix(args[3], 16)?;
        n_bytes = bytes_args;
    }
    let data = process.read_memory(address.into(), n_bytes)?;
    for i in (0..data.len()).step_by(16) {
        let bytes = &data[i..min(i + 16, data.len())];
        let addr = VirtualAddress::from(address) + i as i64;
        let data_msg = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let msg = format!("{:#016x}: {}", addr, data_msg);
        println!("{msg}");
    }
    Ok(())
}

fn handle_memory_write_command(process: &Ref<Process>, args: &[&str]) -> Result<(), SdbError> {
    if args.len() != 4 {
        print_help(&["help", "memory"]);
        return Ok(());
    }
    let address = u64::from_lower_hex_radix(args[2], 16)?;
    let data = parse_vector(args[3])?;
    process.write_memory(address.into(), &data)?;
    Ok(())
}

fn handle_breakpoint_command(
    owned_process: &Rc<RefCell<Process>>,
    args: &[&str],
) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "register"]);
        return Ok(());
    }
    let process = &owned_process.borrow();
    let command = args[1];
    if command == "list" {
        let owned_breakpoint_sites = process.breakpoint_sites();
        let breakpoint_sites = &owned_breakpoint_sites.borrow();
        if breakpoint_sites.empty() {
            println!("No breakpoints set");
        } else {
            println!("Current breakpoints:");
            breakpoint_sites.for_each(|s| {
                let s = &s.borrow();
                let id = s.id();
                let address = s.address().get_addr();
                let status = if s.is_enabled() {
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
        let address = u64::from_lower_hex_radix(args[2], 16);
        if address.is_err() {
            eprintln!("Breakpoint command expects address in hexadecimal, prefixed with '0x'");
            return Ok(());
        }
        let bs = owned_process.create_breakpoint_site(VirtualAddress::from(address.unwrap()))?;
        bs.borrow_mut().enable()?;
        return Ok(());
    }

    let id = IdType::from_lower_hex_radix(args[2], 16)
        .map_err(|_| SdbError::new_err("Command expects breakpoint id"))?;
    let owned_breakpoint_sites = process.breakpoint_sites();
    let breakpoint_sites = &owned_breakpoint_sites.borrow();
    if command == "enable" {
        breakpoint_sites.get_by_id(id)?.borrow_mut().enable()?;
    } else if command == "disable" {
        breakpoint_sites.get_by_id(id)?.borrow_mut().disable()?;
    } else if command == "delete" {
        process.breakpoint_sites().borrow_mut().remove_by_id(id)?;
    }
    return Ok(());
}

fn handle_register_command(process: &Ref<Process>, args: &[&str]) {
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

fn handle_register_read(process: &Ref<Process>, args: &[&str]) {
    if args.len() == 2 || (args.len() == 3 && args[2] == "all") {
        for info in GRegisterInfos {
            let should_print =
                (args.len() == 3 || info.type_ == RegisterType::Gpr) && info.name != "orig_rax";
            if !should_print {
                continue;
            }
            let value = process.get_registers().borrow().read(info);
            println!("{}:\t{}", info.name, value.unwrap());
        }
    } else if args.len() == 3 {
        let info_res = register_info_by_name(args[2]);
        match info_res {
            Ok(info) => {
                let value = process.get_registers().borrow().read(&info);
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

fn handle_register_write(process: &Ref<Process>, args: &[&str]) {
    if args.len() != 4 {
        print_help(&["help", "register"]);
        return;
    }
    if let Err(e) = (|| -> Result<(), SdbError> {
        let info = register_info_by_name(args[2])?;
        let value = parse_register_value(&info, args[3])?;
        process.get_registers().borrow_mut().write(&info, value)?;
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
            disassemble - Disassemble machine code to assembly
            memory - Commands for operating on memory
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
    } else if args[1] == "memory" {
        eprintln!(indoc! {"
            Available commands:
            read <address>
            read <address> <number of bytes>
            write <address> <bytes>
        "});
    } else if args[1] == "disassemble" {
        eprintln!(indoc! {"
            Available options:
            -c <number of instructions>
            -a <start address>
        "});
    }
}
