#![cfg(target_os = "linux")]
#![allow(dead_code)]
#[cfg(not(target_arch = "x86_64"))]
compile_error!("Not x86_64 arch");

use breakpoint_site::IdType;
use disassembler::print_disassembly;
use ffi::sig_abbrev;
use gimli::{DW_AT_location, DW_AT_type, DW_TAG_formal_parameter, DW_TAG_variable};
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
use std::any::{Any, TypeId};
use std::cell::Ref;
use std::cmp::min;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::rc::Rc;
use syscalls::{syscall_id_to_name, syscall_name_to_id};
use target::Target;
use target::TargetExt;
use traits::FromLowerHexStr;
use traits::StoppointTrait;
use types::{StoppointMode, VirtualAddress};
mod breakpoint;
mod breakpoint_site;
mod disassembler;
mod ffi;
mod parse;
mod stack;
mod stoppoint_collection;
mod utils;
mod watchpoint;

pub mod dwarf;
pub mod elf;
pub mod syscalls;
pub mod target;
pub mod traits;
pub use utils::ResultLogExt;

use watchpoint::WatchPoint;

use breakpoint::AddressBreakpoint;
use breakpoint::FunctionBreakpoint;
use breakpoint::LineBreakpoint;

use register_info::RegisterInfo;

use dwarf::DieExt;

use types::TypedData;

use dwarf::DwarfExpressionSimpleLocation;
use register_info::register_info_by_dwarf;

use dwarf::DwarfExpressionResult;

pub mod bit;
pub mod pipe;
pub mod process;
pub mod register_info;
pub mod registers;
pub(crate) mod sdb_error;
pub mod types;

/// Not async-signal-safe
/// https://man7.org/linux/man-pages/man7/signal-safety.7.html
pub fn attach(args: &[&str]) -> Result<Rc<Target>, SdbError> {
    if args.len() == 3 && args[1] == "-p" {
        let pid = Pid::from_raw(args[2].parse().unwrap());
        return Target::attach(pid);
    } else {
        let program_path = args[1];
        let target = Target::launch(Path::new(program_path), None)?;
        let pid = target.get_process().pid();
        println!("Launched process with PID {pid}");
        return Ok(target);
    }
}

fn print_stop_reason(target: &Target, reason: StopReason) -> Result<(), SdbError> {
    let process = &target.get_process();
    let pid = process.pid();
    match reason.reason {
        ProcessState::Exited => {
            let info = reason.info;
            println!("Process {pid} exited with status {info}");
        }
        ProcessState::Terminated => {
            let sig: Signal = reason.info.try_into().unwrap();
            println!("Process {pid} terminated with signal {}", sig.as_str());
        }
        ProcessState::Stopped => {
            get_signal_stop_reason(target, reason)?;
            println!(
                "Thread {} {}",
                reason.tid,
                get_signal_stop_reason(target, reason)?
            );
        }
        ProcessState::Running => {
            eprintln!("Incorrect state");
        }
    };
    Ok(())
}

fn get_signal_stop_reason(target: &Target, reason: StopReason) -> Result<String, SdbError> {
    let process = target.get_process();
    let pc = process.get_pc(Some(reason.tid));
    let mut msg = format!(
        "stopped with signal {} at {:#x}\n",
        sig_abbrev(reason.info),
        pc.addr()
    );
    let line = target.line_entry_at_pc(Some(reason.tid))?;
    if !line.is_end() {
        let file = line
            .get_current()
            .file_entry
            .as_ref()
            .unwrap()
            .path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        msg += &format!("    at {}:{}\n", file, line.get_current().line);
    }
    let func_name = target.function_name_at_address(pc)?;
    if !func_name.is_empty() {
        msg += &format!("    in {func_name}\n");
    }
    if reason.info == SIGTRAP {
        msg += &get_sigtrap_info(&process, reason)?;
    }
    Ok(msg)
}

fn get_sigtrap_info(process: &Process, reason: StopReason) -> Result<String, SdbError> {
    if reason.trap_reason == Some(TrapType::SoftwareBreak) {
        let site = process
            .breakpoint_sites()
            .borrow()
            .get_by_address(process.get_pc(Some(reason.tid)))?;
        return Ok(format!(" (breakpoint {})", site.borrow().id()));
    }
    if reason.trap_reason == Some(TrapType::HardwareBreak) {
        let id = process.get_current_hardware_stoppoint(Some(reason.tid))?;

        match id {
            StoppointId::BreakpointSite(id) => return Ok(format!(" (breakpoint {id})")),
            StoppointId::Watchpoint(id) => {
                let point = process.watchpoints().borrow().get_by_id(id)?;
                let point = point.borrow() as Ref<dyn Any>;
                let point = point.downcast_ref::<WatchPoint>().unwrap();
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
                Ok(format!(" (syscall exit)\nsyscall returned {data:#x}"))
            }
        };
    }

    return Ok("".to_string());
}

pub fn handle_command(target: &Rc<Target>, line: &str) -> Result<(), SdbError> {
    let args: Vec<&str> = line.split(" ").filter(|s| !s.is_empty()).collect();
    let process = &target.get_process();
    let cmd = args[0];
    if cmd == "continue" {
        process.resume_all_threads()?;
        let reason = process.wait_on_signal(Pid::from_raw(-1))?;
        handle_stop(target, reason)?;
    } else if cmd == "help" {
        print_help(&args);
    } else if cmd == "register" {
        handle_register_command(target, &args)?;
    } else if cmd == "breakpoint" {
        handle_breakpoint_command(target, &args)?;
    } else if cmd == "memory" {
        handle_memory_command(process, &args)?;
    } else if cmd == "disassemble" {
        handle_disassemble_command(process, &args)?;
    } else if cmd == "watchpoint" {
        handle_watchpoint_command(process, &args)?;
    } else if cmd == "catchpoint" {
        handle_catchpoint_command(process, &args)?;
    } else if cmd == "next" {
        let reason = target.step_over(None)?;
        handle_stop(target, reason)?;
    } else if cmd == "finish" {
        let reason = target.step_out(None)?;
        handle_stop(target, reason)?;
    } else if cmd == "step" {
        let reason = target.step_in(None)?;
        handle_stop(target, reason)?;
    } else if cmd == "stepi" {
        let reason = process.step_instruction(None)?;
        handle_stop(target, reason)?;
    } else if cmd == "up" {
        target.get_stack(None).borrow_mut().up();
        print_code_location(target)?;
    } else if cmd == "down" {
        target.get_stack(None).borrow_mut().down();
        print_code_location(target)?;
    } else if cmd == "backtrace" {
        print_backtrace(target)?;
    } else if cmd == "thread" {
        handle_thread_command(target, &args)?;
    } else if cmd == "variable" {
        handle_variable_command(target, &args)?;
    } else if cmd == "expression" {
        let expr = &line[line.find(' ').unwrap() + 1..];
        let ret = target.evaluate_expression(expr, None)?;
        if let Some(ret) = ret {
            let str = ret.return_value.visualize(&target.get_process(), 0)?;
            println!("${}: {}", ret.id, str);
        }
    } else {
        eprintln!("Unknown command");
    }
    Ok(())
}

fn handle_variable_command(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "variable"]);
        return Ok(());
    }
    if args[1] == "locals" {
        handle_variable_locals_command(target)?;
        return Ok(());
    }

    if args.len() < 3 {
        print_help(&["help", "variable"]);
        return Ok(());
    }
    if args[1] == "read" {
        handle_variable_read_command(target, args)?;
    } else if args[1] == "location" {
        handle_variable_location_command(target, args)?;
    }
    Ok(())
}

fn handle_variable_location_command(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    let name = args[2];
    let pc = target.get_pc_file_address(None);
    let var = target.find_variable(name, &pc)?;
    if var.is_none() {
        eprintln!("Variable not found");
        return Ok(());
    }
    let var = var.unwrap();
    let loc = var.index(DW_AT_location.0 as u64)?.as_evaluated_location(
        &target.get_process(),
        &target.get_stack(None).borrow().current_frame().registers,
        false,
    )?;
    let print_simple_location = |loc: &DwarfExpressionSimpleLocation| -> Result<(), SdbError> {
        if let DwarfExpressionSimpleLocation::Register { reg_num } = loc {
            let name = register_info_by_dwarf(*reg_num as i32)?.name;
            println!("Register: {name}");
        } else if let DwarfExpressionSimpleLocation::Address { address } = loc {
            println!("Address: {:#x}", address.addr());
        } else {
            println!("None");
        }
        Ok(())
    };

    if let DwarfExpressionResult::SimpleLocation(loc) = loc {
        print_simple_location(&loc)?;
    } else if let DwarfExpressionResult::Pieces(pieces) = loc {
        for piece in pieces.pieces {
            print!(
                "Piece: offset = {}, bit size = {}, location = ",
                piece.offset, piece.bit_size
            );
            print_simple_location(&piece.location)?;
        }
    }
    Ok(())
}

fn handle_variable_read_command(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    let name = args[2];
    let pc = target.get_pc_file_address(None);
    let data = target.resolve_indirect_name(name, &pc)?;
    let str = data.variable.unwrap().visualize(&target.get_process(), 0)?;
    println!("Value: {str}");
    Ok(())
}

fn handle_variable_locals_command(target: &Rc<Target>) -> Result<(), SdbError> {
    let pc = target.get_pc_file_address(None);
    let scopes = pc.rc_elf_file().get_dwarf().scopes_at_address(&pc)?;
    let mut seen = HashSet::new();
    for scope in scopes {
        for var in scope.children() {
            let name = var.name()?.unwrap_or("".to_string());
            let tag = var.abbrev_entry().tag;
            if tag as u16 == DW_TAG_variable.0
                || tag as u16 == DW_TAG_formal_parameter.0
                    && !name.is_empty()
                    && !seen.contains(&name)
            {
                let loc = var.index(DW_AT_location.0 as u64)?.as_evaluated_location(
                    &target.get_process(),
                    &target.get_stack(None).borrow().current_frame().registers,
                    false,
                )?;
                let type_ = var.index(DW_AT_type.0 as u64)?.as_type();
                let value = target.read_location_data(&loc, type_.byte_size()?, None)?;
                let str = TypedData::builder()
                    .data(value)
                    .type_(type_)
                    .build()
                    .visualize(&target.get_process(), 0)?;
                println!("{name}: {str}");
                seen.insert(name);
            }
        }
    }
    Ok(())
}

fn handle_thread_command(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "thread"]);
        return Ok(());
    }
    if args[1] == "list" {
        for (tid, thread) in target.threads().borrow().iter() {
            let prefix = if *tid == target.get_process().current_thread() {
                "*"
            } else {
                " "
            };
            println!(
                "{prefix}Thread {tid}: {}",
                get_signal_stop_reason(target, thread.state.upgrade().unwrap().borrow().reason)?
            );
        }
    } else if args[1] == "select" {
        if args.len() != 3 {
            print_help(&["help", "thread"]);
            return Ok(());
        }
        let tid = i32::from_integral(args[2])?;
        target.get_process().set_current_thread(Pid::from_raw(tid));
    }
    Ok(())
}

fn print_backtrace(target: &Rc<Target>) -> Result<(), SdbError> {
    let stack = target.get_stack(None);
    for (i, frame) in stack.borrow().frames().iter().enumerate() {
        let pc = frame.backtrace_report_address;
        let func_name = target.function_name_at_address(pc)?;

        let mut message = format!(
            "{}[{}]: {:#x} {}",
            if i == stack.borrow().current_frame_index() {
                "*"
            } else {
                " "
            },
            i,
            pc.addr(),
            func_name
        );
        if frame.inlined {
            message += &format!(
                " [inlined] {}",
                frame.func_die.name()?.unwrap_or("".to_string())
            );
        }
        println!("{message}");
    }
    Ok(())
}

fn handle_catchpoint_command(process: &Process, args: &[&str]) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "catchpoint"]);
        return Ok(());
    }
    if args[1] == "syscall" {
        handle_syscall_catchpoint_command(process, args)?;
    }
    Ok(())
}

fn handle_syscall_catchpoint_command(process: &Process, args: &[&str]) -> Result<(), SdbError> {
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

fn handle_watchpoint_command(process: &Rc<Process>, args: &[&str]) -> Result<(), SdbError> {
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
            .watchpoints()
            .borrow()
            .get_by_id(id)?
            .borrow_mut()
            .enable()?;
    } else if command == "disable" {
        process
            .watchpoints()
            .borrow()
            .get_by_id(id)?
            .borrow_mut()
            .disable()?;
    } else if command == "delete" {
        process.watchpoints().borrow_mut().remove_by_id(id)?;
    }
    Ok(())
}

fn handle_watchpoint_list(process: &Process) -> Result<(), SdbError> {
    let watchpoints = process.watchpoints();
    let watchpoints = watchpoints.borrow();
    if watchpoints.empty() {
        println!("No watchpoints set");
    } else {
        println!("Current watchpoints:");
        watchpoints.for_each(|w| {
            let w = w.borrow() as Ref<dyn Any>;
            let w = w.downcast_ref::<WatchPoint>().unwrap();
            println!(
                "{}: address = {:#x}, mode = {}, size = {}, {}",
                w.id(),
                w.address().addr(),
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

fn handle_watchpoint_set(process: &Rc<Process>, args: &[&str]) -> Result<(), SdbError> {
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
        .upgrade()
        .unwrap()
        .borrow_mut()
        .enable()?;
    Ok(())
}

fn handle_disassemble_command(process: &Process, args: &[&str]) -> Result<(), SdbError> {
    let mut address = process.get_pc(None);
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

fn handle_stop(target: &Rc<Target>, reason: StopReason) -> Result<(), SdbError> {
    print_stop_reason(target, reason)?;
    if reason.reason == ProcessState::Stopped {
        print_code_location(target)?;
    }
    Ok(())
}

fn print_code_location(target: &Rc<Target>) -> Result<(), SdbError> {
    if target.get_stack(None).borrow().has_frames() {
        let stack = target.get_stack(None);
        let stack = stack.borrow();
        let frame = stack.current_frame();
        print_source(&frame.location.file.path, frame.location.line, 3)?;
    } else {
        print_disassembly(&target.get_process(), target.get_process().get_pc(None), 5)?;
    }

    Ok(())
}

fn print_source(path: &Path, line: u64, n_lines_context: u64) -> Result<(), SdbError> {
    let file = File::open(path)
        .map_err(|e| SdbError::new_err(&format!("Could not open source file, {e}")))?;
    let reader = BufReader::new(file);

    let start_line = if line <= n_lines_context {
        1
    } else {
        line - n_lines_context
    };
    let end_line = line + n_lines_context + 1;
    let fill_width = ((end_line as f64).log10().floor() as usize) + 1;

    for (idx, line_text) in reader.lines().enumerate() {
        let current_line = (idx + 1) as u64;
        if current_line < start_line {
            continue;
        }
        if current_line > end_line {
            break;
        }
        let text = line_text.map_err(|_| SdbError::new_err("Could not read source file"))?;
        let arrow = if current_line == line { ">" } else { " " };
        println!("{arrow} {current_line:>fill_width$} {text}");
    }

    Ok(())
}

fn handle_memory_command(process: &Process, args: &[&str]) -> Result<(), SdbError> {
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

fn handle_memory_read_command(process: &Process, args: &[&str]) -> Result<(), SdbError> {
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
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let msg = format!("{addr:#016x}: {data_msg}");
        println!("{msg}");
    }
    Ok(())
}

fn handle_memory_write_command(process: &Process, args: &[&str]) -> Result<(), SdbError> {
    if args.len() != 4 {
        print_help(&["help", "memory"]);
        return Ok(());
    }
    let address = u64::from_integral_lower_hex_radix(args[2], 16)?;
    let data = parse_vector(args[3])?;
    process.write_memory(address.into(), &data)?;
    Ok(())
}

fn handle_breakpoint_command(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "register"]);
        return Ok(());
    }
    let command = args[1];
    if command == "list" {
        handle_breakpoint_list_command(target)?;
        return Ok(());
    }

    if args.len() < 3 {
        print_help(&["help", "breakpoint"]);
        return Ok(());
    }

    if command == "set" {
        handle_breakpoint_set_command(target, args)?;
        return Ok(());
    }

    handle_breakpoint_toggle(target, args)?;
    Ok(())
}

fn handle_breakpoint_toggle(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    let command = args[1];
    let dot_pos = args[2].find('.').unwrap_or(args[2].len());
    let id_str = &args[2][..dot_pos];
    let id = IdType::from_integral(id_str)
        .map_err(|_| SdbError::new_err("Command expects breakpoint id"))?;
    let bp = target.breakpoints().borrow().get_by_id(id)?;
    if dot_pos != args[2].len() {
        let site_id_str = &args[2][dot_pos + 1..];
        let site_id = IdType::from_integral(site_id_str)
            .map_err(|_| SdbError::new_err("Command expects breakpoint site id"))?;
        let site = bp.borrow().breakpoint_sites().get_by_id(site_id)?;
        if command == "enable" {
            site.borrow_mut().enable()?;
        } else if command == "disable" {
            site.borrow_mut().disable()?;
        }
    } else if command == "enable" {
        bp.borrow_mut().enable()?;
    } else if command == "disable" {
        bp.borrow_mut().disable()?;
    } else if command == "delete" {
        for site in bp.borrow_mut().breakpoint_sites().iter() {
            target
                .get_process()
                .breakpoint_sites()
                .borrow_mut()
                .remove_by_address(site.borrow().address())?;
        }
        target.breakpoints().borrow_mut().remove_by_id(id)?;
    }
    Ok(())
}

fn handle_breakpoint_list_command(target: &Rc<Target>) -> Result<(), SdbError> {
    let breakpoints = target.breakpoints().borrow();
    if breakpoints.empty() {
        println!("No breakpoints set");
    } else {
        println!("Current breakpoints:");
        for bp in breakpoints.iter() {
            if bp.borrow().is_internal() {
                continue;
            }
            print!("{}: ", bp.borrow().id());

            match (&*bp.borrow() as &dyn Any).type_id() {
                id if id == TypeId::of::<AddressBreakpoint>() => {
                    print!(
                        "address = {:#x}",
                        (bp.borrow() as Ref<dyn Any>)
                            .downcast_ref::<AddressBreakpoint>()
                            .unwrap()
                            .address()
                    );
                }
                id if id == TypeId::of::<FunctionBreakpoint>() => {
                    print!(
                        "function = {}",
                        (bp.borrow() as Ref<dyn Any>)
                            .downcast_ref::<FunctionBreakpoint>()
                            .unwrap()
                            .function_name()
                    );
                }
                id if id == TypeId::of::<LineBreakpoint>() => {
                    print!(
                        "file = {}, line = {}",
                        (bp.borrow() as Ref<dyn Any>)
                            .downcast_ref::<LineBreakpoint>()
                            .unwrap()
                            .file()
                            .to_str()
                            .unwrap(),
                        (bp.borrow() as Ref<dyn Any>)
                            .downcast_ref::<LineBreakpoint>()
                            .unwrap()
                            .line()
                    );
                }
                _ => {}
            }
            println!(
                ", {}",
                if bp.borrow().is_enabled() {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            bp.borrow().breakpoint_sites().for_each(|site| {
                println!(
                    " .{}: address = {:#x}, {}",
                    site.borrow().id(),
                    site.borrow().address().addr(),
                    if site.borrow().is_enabled() {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
            });
        }
    }
    Ok(())
}

fn handle_breakpoint_set_command(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    let mut hardware = false;
    if args.len() == 4 {
        if args[3] == "-h" {
            hardware = true;
        } else {
            return SdbError::err("Invalid breakpoint command argument");
        }
    }
    if args[2].starts_with("0x") {
        let address = u64::from_integral_lower_hex_radix(args[2], 16);
        match address {
            Ok(address) => {
                target
                    .create_address_breakpoint(address.into(), hardware, false)?
                    .upgrade()
                    .unwrap()
                    .borrow_mut()
                    .enable()?;
            }
            Err(_) => {
                return SdbError::err(
                    "Breakpoint command expects address in hexadecimal, prefixed with '0x'",
                );
            }
        }
    } else if args[2].contains(':') {
        let mut data = args[2].split(':');
        let path = data.next().unwrap();
        let line = u64::from_integral(data.next().unwrap());
        match line {
            Ok(line) => {
                target
                    .create_line_breakpoint(Path::new(path), line as usize, hardware, false)?
                    .upgrade()
                    .unwrap()
                    .borrow_mut()
                    .enable()?;
            }
            Err(_) => {
                return SdbError::err("Line number should be an integer");
            }
        }
    } else {
        target
            .create_function_breakpoint(args[2], false, false)?
            .upgrade()
            .unwrap()
            .borrow_mut()
            .enable()?;
    }
    Ok(())
}

fn handle_register_command(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    if args.len() < 2 {
        print_help(&["help", "register"]);
        return Ok(());
    }

    if args[1] == "read" {
        handle_register_read(target, args)?;
    } else if args[1] == "write" {
        handle_register_write(&target.get_process(), args);
    } else {
        print_help(&["help", "register"]);
    }
    Ok(())
}

fn handle_register_read(target: &Rc<Target>, args: &[&str]) -> Result<(), SdbError> {
    let stack = target.get_stack(None);
    let stack = stack.borrow();
    let regs = stack.regs();

    let print_reg_info = |info: &RegisterInfo| -> Result<(), SdbError> {
        if regs.is_undefined(info.id)? {
            println!("{}:\tundefined", info.name);
        } else {
            let value = regs.read(info)?;
            println!("{}:\t{}", info.name, value);
        }
        Ok(())
    };
    if args.len() == 2 || (args.len() == 3 && args[2] == "all") {
        for info in GRegisterInfos {
            if args.len() == 3 || info.type_ == RegisterType::Gpr {
                print_reg_info(info)?;
            }
        }
    } else if args.len() == 3 {
        let info_res = register_info_by_name(args[2]);
        match info_res {
            Ok(info) => {
                print_reg_info(&info)?;
            }
            Err(_) => {
                eprintln!("No such register")
            }
        }
    } else {
        print_help(&["help", "register"]);
    }
    Ok(())
}

fn handle_register_write(process: &Process, args: &[&str]) {
    if args.len() != 4 {
        print_help(&["help", "register"]);
        return;
    }
    if let Err(e) = (|| -> Result<(), SdbError> {
        let info = register_info_by_name(args[2])?;
        let value = parse_register_value(&info, args[3])?;
        process
            .get_registers(None)
            .borrow_mut()
            .write(&info, value, true)?;
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
            catchpoint - Commands for operating on catchpoints
            continue - Resume the process
            disassemble - Disassemble machine code to assembly
            finish - Step-out
            memory - Commands for operating on memory
            next - Step-over
            register - Commands for operating on registers
            step - Step-in
            stepi - Single instruction step
            watchpoint - Commands for operating on watchpoints
            down        - Select the stack frame below the current one
            up          - Select the stack frame above the current one
            thread      - Commands for operating on threads
            variable    - Commands for operating on variables
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
    } else if args[1] == "thread" {
        eprintln!(indoc! {"
            Available commands:
            list
            select <thread ID>
        "})
    } else if args[1] == "variable" {
        eprintln!(indoc! {"
            Available commands:
            read <variable>
        "})
    }
}
