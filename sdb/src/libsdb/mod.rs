#![cfg(target_os = "linux")]
#![allow(dead_code)]

use breakpoint_site::IdType;
use disassembler::print_disassembly;
use indoc::indoc;
use nix::libc::SIGTRAP;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use parse::{parse_register_value, parse_vector};
use process::{
    Process, ProcessExt, ProcessState, StopReason, StoppointId, SyscallCatchPolicy, TrapType,
};
use register_info::{GRegisterInfos, RegisterType, register_info_by_name};
use sdb_error::SdbError;
use std::cell::{Ref, RefCell};
use std::cmp::min;
use std::path::Path;
use std::{ffi::CString, rc::Rc};
use syscalls::{syscall_id_to_name, syscall_name_to_id};
use traits::FromLowerHexStr;
use traits::StoppointTrait;
use types::{StoppointMode, VirtualAddress};

mod breakpoint_site;
mod disassembler;
mod elf;
mod parse;
mod stoppoint_collection;
mod utils;
mod watchpoint;

pub mod syscalls;
pub mod traits;
pub use utils::ResultLogExt;
pub mod bit;
pub mod pipe;
pub mod process;
pub mod register_info;
pub mod registers;
pub(crate) mod sdb_error;
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

fn print_stop_reason(process: &Ref<Process>, reason: StopReason) -> Result<(), SdbError> {
    let pid = process.pid();
    let msg_start = format!("Process {pid}");
    let msg = match reason.reason {
        ProcessState::Exited => {
            let info = reason.info;
            format!("{msg_start} exited with status {info}")
        }
        ProcessState::Terminated => {
            let sig: Signal = reason.info.try_into().unwrap();
            format!("{msg_start} terminated with signal {}", sig.as_str())
        }
        ProcessState::Stopped => {
            let sig: Signal = reason.info.try_into().unwrap();
            let addr = process.get_pc();
            let mut msg = format!(
                "{msg_start} stopped with signal {} at {addr:#x}",
                sig.as_str()
            );
            if reason.info == SIGTRAP {
                msg += &get_sigtrap_info(process, reason)?;
            }
            msg
        }
        ProcessState::Running => {
            eprintln!("Incorrect state");
            String::new()
        }
    };
    println!("{msg}");
    Ok(())
}

fn get_sigtrap_info(process: &Ref<Process>, reason: StopReason) -> Result<String, SdbError> {
    if reason.trap_reason == Some(TrapType::SoftwareBreak) {
        let site = process
            .breakpoint_sites()
            .borrow()
            .get_by_address(process.get_pc())?;
        return Ok(format!(" (breakpoint {})", site.borrow().id()));
    }
    if reason.trap_reason == Some(TrapType::HardwareBreak) {
        let id = process.get_current_hardware_stoppoint()?;

        match id {
            StoppointId::BreakpointSite(id) => return Ok(format!(" (breakpoint {id})")),
            StoppointId::Watchpoint(id) => {
                let point = process.watchpoints().borrow().get_by_id(id)?;
                let point = point.borrow();
                let mut msg = format!(" (watchpoint {})", point.id());
                if point.data() == point.previous_data() {
                    msg += &format!("\nValue: {:#x}", point.data());
                } else {
                    msg += &format!(
                        "\nOld value: {:#x}\nNew value: {:#x}",
                        point.previous_data(),
                        point.data()
                    );
                }
                return Ok(msg);
            }
        }
    }

    if reason.trap_reason == Some(TrapType::SingleStep) {
        return Ok(" (single step)".to_string());
    }
    if reason.trap_reason == Some(TrapType::Syscall) {
        let info = reason.syscall_info.as_ref().unwrap();
        return match info.data {
            process::SyscallData::Args(data) => Ok(format!(
                " (syscall entry)\nsyscall: {}({})",
                syscall_id_to_name(info.id as i64)?,
                data.iter()
                    .map(|d| { format!("{d:#x}") })
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            process::SyscallData::Ret(data) => {
                Ok(format!(" (syscall exit)\nsyscall returned {:#x}", data))
            }
        };
    }

    return Ok("".to_string());
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
        handle_disassemble_command(process, &args)?;
    } else if cmd == "watchpoint" {
        handle_watchpoint_command(owned_process, &args)?;
    } else if cmd == "catchpoint" {
        handle_catchpoint_command(process, &args)?;
    } else {
        eprintln!("Unknown command");
    }
    Ok(())
}

fn handle_catchpoint_command(process: &Ref<Process>, args: &[&str]) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "catchpoint"]);
        return Ok(());
    }
    if args[1] == "syscall" {
        handle_syscall_catchpoint_command(process, args)?;
    }
    Ok(())
}

fn handle_syscall_catchpoint_command(
    process: &Ref<Process>,
    args: &[&str],
) -> Result<(), SdbError> {
    let mut policy = SyscallCatchPolicy::All;
    if args.len() == 3 && args[2] == "none" {
        policy = SyscallCatchPolicy::None;
    } else if args.len() >= 3 {
        let syscalls: Vec<_> = args[2]
            .split(",")
            .map(|s| s.trim())
            .map(|s| {
                if is_digits(s) {
                    i32::from_integral(s)
                } else {
                    syscall_name_to_id(s).map(|d| d as i32)
                }
            })
            .collect();
        let to_catch: Result<Vec<_>, _> = syscalls.into_iter().collect();
        policy = SyscallCatchPolicy::Some(to_catch?);
    }
    process.set_syscall_catch_policy(policy);
    Ok(())
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn handle_watchpoint_command(
    process: &Rc<RefCell<Process>>,
    args: &[&str],
) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "watchpoint"]);
        return Ok(());
    }
    let command = args[1];
    if command == "list" {
        handle_watchpoint_list(process)?;
        return Ok(());
    }

    if command == "set" {
        handle_watchpoint_set(process, args)?;
        return Ok(());
    }

    if args.len() < 3 {
        print_help(&["help", "watchpoint"]);
        return Ok(());
    }

    let id = args[2]
        .parse::<IdType>()
        .map_err(|_| SdbError::new_err("Command expects watchpoint id"))?;
    if command == "enable" {
        process
            .borrow()
            .watchpoints()
            .borrow()
            .get_by_id(id)?
            .borrow_mut()
            .enable()?;
    } else if command == "disable" {
        process
            .borrow()
            .watchpoints()
            .borrow()
            .get_by_id(id)?
            .borrow_mut()
            .disable()?;
    } else if command == "delete" {
        process
            .borrow()
            .watchpoints()
            .borrow_mut()
            .remove_by_id(id)?;
    }
    Ok(())
}

fn handle_watchpoint_list(process: &Rc<RefCell<Process>>) -> Result<(), SdbError> {
    let process = process.borrow();
    let watchpoints = process.watchpoints();
    let watchpoints = watchpoints.borrow();
    if watchpoints.empty() {
        println!("No watchpoints set");
    } else {
        println!("Current watchpoints:");
        watchpoints.for_each(|w| {
            let w = w.borrow();
            println!(
                "{}: address = {:#x}, mode = {}, size = {}, {}",
                w.id(),
                w.address().get_addr(),
                w.mode(),
                w.size(),
                if w.is_enabled() {
                    "enabled"
                } else {
                    "disabled"
                }
            )
        });
    }
    Ok(())
}

fn handle_watchpoint_set(process: &Rc<RefCell<Process>>, args: &[&str]) -> Result<(), SdbError> {
    if args.len() != 5 {
        print_help(&["help", "watchpoint"]);
        return Ok(());
    }
    let address = u64::from_integral_lower_hex_radix(args[2], 16)?;
    let mode_text = args[3];
    let size = usize::from_integral(args[4])?;
    if !(mode_text == "write" || mode_text == "rw" || mode_text == "execute") {
        print_help(&["help", "watchpoint"]);
        return Ok(());
    }
    let mode: StoppointMode = match mode_text {
        "write" => StoppointMode::Write,
        "rw" => StoppointMode::ReadWrite,
        "execute" => StoppointMode::Execute,
        _ => panic!(),
    };
    process
        .create_watchpoint(address.into(), mode, size)?
        .borrow_mut()
        .enable()?;
    Ok(())
}

fn handle_disassemble_command(process: &Ref<Process>, args: &[&str]) -> Result<(), SdbError> {
    let mut address = process.get_pc();
    let mut n_instructions = 5usize;
    let mut args_iter = args.iter();
    args_iter.next();
    while let Some(data) = args_iter.next() {
        match *data {
            "-a" => {
                let opt_addr = args_iter
                    .next()
                    .ok_or(SdbError::new_err("Invalid address format"))?;
                address = u64::from_integral_lower_hex_radix(opt_addr, 16)?.into();
            }
            "-c" => {
                let instruction_count = args_iter
                    .next()
                    .ok_or(SdbError::new_err("Invalid instruction count"))?;
                n_instructions = usize::from_integral(instruction_count)?;
            }
            _ => {
                print_help(&["help", "disassemble"]);
                return Ok(());
            }
        }
    }

    print_disassembly(process, address, n_instructions)?;
    Ok(())
}

fn handle_stop(process: &Rc<RefCell<Process>>, reason: StopReason) -> Result<(), SdbError> {
    let ref_process = &process.borrow();
    print_stop_reason(ref_process, reason)?;
    if reason.reason == ProcessState::Stopped {
        print_disassembly(ref_process, ref_process.get_pc(), 5)?;
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
    let address = u64::from_integral_lower_hex_radix(args[2], 16)?;
    let mut n_bytes = 32usize;
    if args.len() == 4 {
        let bytes_args = usize::from_integral_lower_hex_radix(args[3], 16)?;
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
    let address = u64::from_integral_lower_hex_radix(args[2], 16)?;
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
                if s.is_internal() {
                    return;
                }
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
        let address = u64::from_integral_lower_hex_radix(args[2], 16);
        if address.is_err() {
            eprintln!("Breakpoint command expects address in hexadecimal, prefixed with '0x'");
            return Ok(());
        }
        let mut hardware = false;
        if args.len() == 4 {
            if args[3] == "-h" {
                hardware = true;
            } else {
                return SdbError::err("Invalid breakpoint command argument");
            }
        }
        let bs = owned_process.create_breakpoint_site(
            VirtualAddress::from(address.unwrap()),
            hardware,
            false,
        )?;
        bs.borrow_mut().enable()?;
        return Ok(());
    }

    let id = IdType::from_integral_lower_hex_radix(args[2], 16)
        .map_err(|_| SdbError::new_err("Command expects breakpoint id"))?;
    if command == "enable" {
        process
            .breakpoint_sites()
            .borrow()
            .get_by_id(id)?
            .borrow_mut()
            .enable()?;
    } else if command == "disable" {
        process
            .breakpoint_sites()
            .borrow()
            .get_by_id(id)?
            .borrow_mut()
            .disable()?;
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
            watchpoint - Commands for operating on watchpoints
            catchpoint - Commands for operating on catchpoints
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
            set <address> -h
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
    } else if args[1] == "watchpoint" {
        eprintln!(indoc! {"
            Available commands:
            list
            delete <id>
            disable <id>
            enable <id>
            set <address> <write|rw|execute> <size>
        "})
    } else if args[1] == "catchpoint" {
        eprintln!(indoc! {"
            Available commands:
            syscall
            syscall none
            syscall <list of syscall IDs or names>
        "})
    }
}
