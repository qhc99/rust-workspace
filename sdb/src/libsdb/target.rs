use std::any::Any;
use std::cell::{Ref, RefCell, RefMut};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};

use elf::abi::STT_FUNC;
use goblin::elf::sym::st_type;
use nix::libc::{AT_ENTRY, SIGTRAP};
use nix::unistd::Pid;

use super::ffi::r_debug;

use super::breakpoint::Breakpoint;

use super::ffi::demangle;

use super::breakpoint::AddressBreakpoint;
use super::breakpoint::FunctionBreakpoint;
use super::breakpoint::LineBreakpoint;

use super::stoppoint_collection::StoppointCollection;

use super::dwarf::Die;
use super::elf::SdbElf64Sym;

use super::disassembler::Disassembler;
use super::dwarf::LineTableExt;
use super::dwarf::LineTableIter;
use super::elf::Elf;
use super::process::Process;
use super::process::ProcessExt;
use super::process::StopReason;
use super::process::{ProcessState, TrapType};
use super::register_info::RegisterId;
use super::sdb_error::SdbError;
use super::stack::Stack;
use super::traits::StoppointTrait;
use super::types::FileAddress;
use super::types::VirtualAddress;

pub struct Target {
    process: Rc<Process>,
    elf: Rc<Elf>,
    stack: RefCell<Stack>,
    breakpoints: RefCell<StoppointCollection>,
    dynamic_linker_rendezvous_address: RefCell<VirtualAddress>,
}

impl Target {
    fn new(process: Rc<Process>, elf: Rc<Elf>) -> Rc<Self> {
        Rc::new_cyclic(|weak_self| Self {
            process: process.clone(),
            elf: elf.clone(),
            stack: RefCell::new(Stack::new(weak_self)),
            breakpoints: RefCell::new(StoppointCollection::default()),
            dynamic_linker_rendezvous_address: RefCell::new(VirtualAddress::default()),
        })
    }

    pub fn get_stack(&self) -> Ref<Stack> {
        self.stack.borrow()
    }

    pub fn get_stack_mut(&self) -> RefMut<Stack> {
        self.stack.borrow_mut()
    }

    pub fn launch(path: &Path, stdout_replacement: Option<i32>) -> Result<Rc<Self>, SdbError> {
        let proc = Process::launch(path, true, stdout_replacement)?;
        let obj = create_loaded_elf(&proc, path)?;
        let tgt = Target::new(proc, obj);
        tgt.process.set_target(&tgt);
        let entry_point = VirtualAddress::new(tgt.get_process().get_auxv()[&(AT_ENTRY as i32)]);
        let entry_bp = tgt.create_address_breakpoint(entry_point, false, true)?;
        let entry_bp = entry_bp.upgrade().unwrap();
        let entry_bp = entry_bp.borrow_mut();
        let mut entry_bp = entry_bp as RefMut<'_, dyn Any>;
        let entry_bp = entry_bp.downcast_mut::<Breakpoint>().unwrap();
        let tgt_clone = tgt.clone();
        entry_bp.install_hit_handler(move || {
            tgt_clone.resolve_dynamic_linker_rendezvous();
            true
        });
        entry_bp.enable()?;
        Ok(tgt)
    }

    pub fn attach(pid: Pid) -> Result<Rc<Self>, SdbError> {
        let elf_path = PathBuf::from("/proc").join(pid.to_string()).join("exe");
        let proc = Process::attach(pid)?;
        let obj = create_loaded_elf(&proc, &elf_path)?;
        let tgt = Target::new(proc, obj);
        tgt.process.set_target(&tgt);
        tgt.resolve_dynamic_linker_rendezvous();
        Ok(tgt)
    }

    pub fn get_process(&self) -> Rc<Process> {
        self.process.clone()
    }

    pub fn get_elf(&self) -> Rc<Elf> {
        self.elf.clone()
    }

    pub fn notify_stop(&self, _reason: &StopReason) -> Result<(), SdbError> {
        self.stack.borrow_mut().unwind()
    }

    pub fn get_pc_file_address(&self) -> FileAddress {
        self.process.get_pc().to_file_addr(&self.elf)
    }

    pub fn step_in(&self) -> Result<StopReason, SdbError> {
        if self.get_stack().inline_height() > 0 {
            self.get_stack_mut().simulate_inlined_step_in();
            return Ok(StopReason::builder()
                .reason(ProcessState::Stopped)
                .info(SIGTRAP)
                .trap_reason(Some(TrapType::SingleStep))
                .build());
        }
        let orig_line = self.line_entry_at_pc()?;
        loop {
            let reason = self.process.step_instruction()?;
            if !reason.is_step() {
                return Ok(reason);
            }
            if !((self.line_entry_at_pc()? == orig_line
                || self.line_entry_at_pc()?.get_current().end_sequence)
                && !self.line_entry_at_pc()?.is_end())
            {
                break;
            }
        }
        let pc = self.get_pc_file_address();
        if pc.has_elf() {
            let dwarf = pc.rc_elf_file().get_dwarf();
            let func = dwarf.function_containing_address(&pc)?;
            if func.is_some() && func.as_ref().unwrap().low_pc()? == pc {
                let mut line = self.line_entry_at_pc()?;
                if !line.is_end() {
                    line.step()?;
                    return self.run_until_address(line.get_current().address.to_virt_addr());
                }
            }
        }
        Ok(StopReason::builder()
            .reason(ProcessState::Stopped)
            .info(SIGTRAP)
            .trap_reason(Some(TrapType::SingleStep))
            .build())
    }

    pub fn step_out(&self) -> Result<StopReason, SdbError> {
        let inline_stack = self.get_stack().inline_stack_at_pc()?;
        let has_inline_frames = inline_stack.len() > 1;
        let at_inline_frame =
            (self.get_stack().inline_height() as usize) < (inline_stack.len() - 1);
        if has_inline_frames && at_inline_frame {
            let current_frame =
                &inline_stack[inline_stack.len() - self.get_stack().inline_height() as usize - 1];
            let return_address = current_frame.high_pc()?.to_virt_addr();
            return self.run_until_address(return_address);
        }
        let stack = self.stack.borrow();
        let regs = &stack.frames()[stack.current_frame_index() + 1].registers;
        let return_address = VirtualAddress::new(regs.read_by_id_as::<u64>(RegisterId::rip)?);
        let mut reason = StopReason::default();
        drop(stack);
        let frames = self.stack.borrow().frames().len();
        while self.stack.borrow().frames().len() >= frames {
            reason = self.run_until_address(return_address)?;
            if !reason.is_breakpoint() || self.process.get_pc() != return_address {
                return Ok(reason);
            }
        }
        Ok(reason)
    }

    pub fn step_over(&self) -> Result<StopReason, SdbError> {
        let orig_line = self.line_entry_at_pc()?;
        let disas = Disassembler::new(&self.process);
        let mut reason;
        loop {
            let inline_stack = self.get_stack().inline_stack_at_pc()?;
            let at_start_of_inline_frame = self.get_stack().inline_height() > 0;
            if at_start_of_inline_frame {
                let frame_to_skip =
                    &inline_stack[inline_stack.len() - self.get_stack().inline_height() as usize];
                let return_address = frame_to_skip.high_pc()?.to_virt_addr();
                reason = self.run_until_address(return_address)?;
                if !reason.is_step() || self.process.get_pc() != return_address {
                    return Ok(reason);
                }
            } else {
                let instructions = disas.disassemble(2, Some(self.process.get_pc()))?;
                if instructions[0].text.rfind("call") == Some(0) {
                    reason = self.run_until_address(instructions[1].address)?;
                    if !reason.is_step() || self.process.get_pc() != instructions[1].address {
                        return Ok(reason);
                    }
                } else {
                    reason = self.process.step_instruction()?;
                    if !reason.is_step() {
                        return Ok(reason);
                    }
                }
            }

            if !((self.line_entry_at_pc()? == orig_line
                || self.line_entry_at_pc()?.get_current().end_sequence)
                && !self.line_entry_at_pc()?.is_end())
            {
                break;
            }
        }
        Ok(reason)
    }

    pub fn line_entry_at_pc(&self) -> Result<LineTableIter, SdbError> {
        let pc = self.get_pc_file_address();
        if !pc.has_elf() {
            return Ok(LineTableIter::default());
        }
        let dwarf = pc.rc_elf_file().get_dwarf();
        let cu = dwarf.compile_unit_containing_address(&pc)?;
        if cu.is_none() {
            return Ok(LineTableIter::default());
        }
        cu.unwrap().lines().get_entry_by_address(&pc)
    }

    fn run_until_address(&self, address: VirtualAddress) -> Result<StopReason, SdbError> {
        let mut breakpoint_to_remove = None;
        if !self
            .process
            .breakpoint_sites()
            .borrow()
            .contains_address(address)
        {
            breakpoint_to_remove = Some(self.process.create_breakpoint_site(address, false, true)?);
            breakpoint_to_remove
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap()
                .borrow_mut()
                .enable()?;
        }
        self.process.resume()?;
        let mut reason = self.process.wait_on_signal()?;
        if reason.is_breakpoint() && self.process.get_pc() == address {
            reason.trap_reason = Some(TrapType::SingleStep);
        }
        if breakpoint_to_remove.is_some() {
            self.process
                .breakpoint_sites()
                .borrow_mut()
                .remove_by_address({
                    breakpoint_to_remove
                        .unwrap()
                        .upgrade()
                        .unwrap()
                        .borrow()
                        .address()
                })?;
        }
        Ok(reason)
    }

    pub fn find_functions(&self, name: &str) -> Result<FindFunctionsResult, SdbError> {
        let mut result = FindFunctionsResult {
            dwarf_functions: Vec::new(),
            elf_functions: Vec::new(),
        };
        let dwarf_found = self.elf.get_dwarf().find_functions(name)?;
        if dwarf_found.is_empty() {
            let elf_found = self.elf.get_symbols_by_name(name);
            for sym in &elf_found {
                result.elf_functions.push((self.elf.clone(), sym.clone()));
            }
        } else {
            result.dwarf_functions.extend(dwarf_found);
        }
        Ok(result)
    }

    pub fn breakpoints(&self) -> &RefCell<StoppointCollection> {
        &self.breakpoints
    }

    pub fn function_name_at_address(&self, address: VirtualAddress) -> Result<String, SdbError> {
        let file_address = address.to_file_addr(&self.elf);
        if !file_address.has_elf() {
            return Ok(String::new());
        }
        let obj = file_address.rc_elf_file();
        let func = obj.get_dwarf().function_containing_address(&file_address)?;
        if func.is_some() {
            return Ok(func.unwrap().name()?.unwrap());
        } else {
            let elf_func = obj.get_symbol_containing_file_address(file_address);
            if elf_func.is_some() && st_type(elf_func.as_ref().unwrap().0.st_info) == STT_FUNC {
                let elf_name = obj.get_string(elf_func.as_ref().unwrap().0.st_name as usize);
                let demangled = demangle(elf_name).unwrap_or_default();
                return Ok(demangled);
            }
        }
        Ok(String::new())
    }

    pub fn read_dynamic_linker_rendezvous(&self) -> Option<r_debug> {
        todo!()
    }


    fn resolve_dynamic_linker_rendezvous(&self) -> Result<(), SdbError> {
        if self.dynamic_linker_rendezvous_address.borrow().addr() != 0 {
            return Ok(());
        }

        let dynamic_section = match self.elf.get_section(".dynamic") {
            Some(section) => section,
            None => return Ok(()),
        };

        let dynamic_start = FileAddress::new(&self.elf, dynamic_section.0.sh_addr);
        let dynamic_size = dynamic_section.0.sh_size as usize;
        let dynamic_bytes = self.process.read_memory(
            dynamic_start.to_virt_addr(),
            dynamic_size,
        )?;

        let entry_size = std::mem::size_of::<super::ffi::Elf64_Dyn>();
        let num_entries = dynamic_size / entry_size;

        for i in 0..num_entries {
            let start_idx = i * entry_size;
            let end_idx = start_idx + entry_size;
            if end_idx > dynamic_bytes.len() {
                break;
            }

            let entry_bytes = &dynamic_bytes[start_idx..end_idx];
            let entry: super::ffi::Elf64_Dyn = unsafe {
                std::ptr::read(entry_bytes.as_ptr() as *const super::ffi::Elf64_Dyn)
            };

            if entry.d_tag == super::ffi::DT_DEBUG as u64 {
                let rendezvous_addr = VirtualAddress::new(unsafe { entry.d_un.d_ptr });
                *self.dynamic_linker_rendezvous_address.borrow_mut() = rendezvous_addr;
                self.reload_dynamic_libraries();

                if let Some(debug_info) = self.read_dynamic_linker_rendezvous() {
                    let debug_state_addr = VirtualAddress::new(debug_info.r_brk as u64);
                    match self.create_address_breakpoint(debug_state_addr, false, true) {
                        Ok(debug_state_bp) => {
                            if let Some(bp) = debug_state_bp.upgrade() {
                                let mut bp_ref = bp.borrow_mut();
                                let bp_any = bp_ref.as_mut() as &mut dyn std::any::Any;
                                if let Some(breakpoint) = bp_any.downcast_mut::<super::breakpoint::Breakpoint>() {
                                    let target_clone = self as *const Self;
                                    breakpoint.install_hit_handler(move || {
                                        unsafe {
                                            (*target_clone).reload_dynamic_libraries();
                                        }
                                        true
                                    });
                                    let _ = breakpoint.enable();
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
                break;
            }
        }

        Ok(())
    }

    fn reload_dynamic_libraries(&self) {
        todo!()
    }
}

pub trait TargetExt {
    fn create_address_breakpoint(
        &self,
        address: VirtualAddress,
        is_hardware: bool,
        is_internal: bool,
    ) -> Result<Weak<RefCell<dyn StoppointTrait>>, SdbError>;

    fn create_function_breakpoint(
        &self,
        function_name: &str,
        is_hardware: bool,
        is_internal: bool,
    ) -> Result<Weak<RefCell<dyn StoppointTrait>>, SdbError>;

    fn create_line_breakpoint(
        &self,
        file: &Path,
        line: usize,
        is_hardware: bool,
        is_internal: bool,
    ) -> Result<Weak<RefCell<dyn StoppointTrait>>, SdbError>;
}

impl TargetExt for Rc<Target> {
    fn create_address_breakpoint(
        &self,
        address: VirtualAddress,
        is_hardware: bool,
        is_internal: bool,
    ) -> Result<Weak<RefCell<dyn StoppointTrait>>, SdbError> {
        let breakpoint = Rc::new(RefCell::new(AddressBreakpoint::new(
            self,
            address,
            is_hardware,
            is_internal,
        )?));
        let breakpoint = self
            .breakpoints
            .borrow_mut()
            .push_strong(breakpoint.clone());
        Ok(breakpoint)
    }

    fn create_function_breakpoint(
        &self,
        function_name: &str,
        is_hardware: bool,
        is_internal: bool,
    ) -> Result<Weak<RefCell<dyn StoppointTrait>>, SdbError> {
        let breakpoint = Rc::new(RefCell::new(FunctionBreakpoint::new(
            self,
            function_name,
            is_hardware,
            is_internal,
        )?));
        let breakpoint = self
            .breakpoints
            .borrow_mut()
            .push_strong(breakpoint.clone());
        Ok(breakpoint)
    }

    fn create_line_breakpoint(
        &self,
        file: &Path,
        line: usize,
        is_hardware: bool,
        is_internal: bool,
    ) -> Result<Weak<RefCell<dyn StoppointTrait>>, SdbError> {
        let breakpoint = Rc::new(RefCell::new(LineBreakpoint::new(
            self,
            file,
            line,
            is_hardware,
            is_internal,
        )?));
        let breakpoint = self
            .breakpoints
            .borrow_mut()
            .push_strong(breakpoint.clone());
        Ok(breakpoint)
    }
}

pub struct FindFunctionsResult {
    pub dwarf_functions: Vec<Rc<Die>>,
    pub elf_functions: Vec<(Rc<Elf>, Rc<SdbElf64Sym>)>,
}

fn create_loaded_elf(proc: &Process, path: &Path) -> Result<Rc<Elf>, SdbError> {
    let auxv = proc.get_auxv();
    let obj = Elf::new(path)?;
    obj.notify_loaded(VirtualAddress::new(
        auxv[&(AT_ENTRY as i32)] - obj.get_header().0.e_entry,
    ));
    Ok(obj)
}
