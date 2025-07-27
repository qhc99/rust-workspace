use std::any::Any;
use std::cell::{Ref, RefCell, RefMut};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};

use elf::abi::STT_FUNC;
use goblin::elf::sym::st_type;
use nix::libc::{AT_ENTRY, SIGTRAP};
use nix::unistd::Pid;

use super::elf::SdbElf64Ehdr;

use super::elf::ElfCollection;

use super::ffi::r_debug;

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
    main_elf: Weak<Elf>,
    elves: RefCell<ElfCollection>,
    stack: RefCell<Stack>,
    breakpoints: RefCell<StoppointCollection>,
    dynamic_linker_rendezvous_address: RefCell<VirtualAddress>,
}

impl Target {
    fn new(process: Rc<Process>, elf: Rc<Elf>) -> Rc<Self> {
        Rc::new_cyclic(|weak_self| Self {
            process: process.clone(),
            main_elf: Rc::downgrade(&elf),
            elves: RefCell::new({
                let mut t = ElfCollection::default();
                t.push(elf.clone());
                t
            }),
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
        let entry_bp = entry_bp.downcast_mut::<AddressBreakpoint>().unwrap();
        let tgt_clone = tgt.clone();
        entry_bp
            .breakpoint
            .borrow_mut()
            .install_hit_handler(move || {
                tgt_clone.resolve_dynamic_linker_rendezvous()?;
                Ok(true)
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
        tgt.resolve_dynamic_linker_rendezvous()?;
        Ok(tgt)
    }

    pub fn get_process(&self) -> Rc<Process> {
        self.process.clone()
    }

    pub fn get_main_elf(&self) -> Weak<Elf> {
        self.main_elf.clone()
    }

    pub fn notify_stop(&self, _reason: &StopReason) -> Result<(), SdbError> {
        self.stack.borrow_mut().unwind()
    }

    pub fn get_pc_file_address(&self) -> FileAddress {
        self.process
            .get_pc()
            .to_file_addr_elves(&self.elves.borrow())
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
        for elf in self.elves.borrow().iter() {
            let dwarf_found = elf.get_dwarf().find_functions(name)?;
            if dwarf_found.is_empty() {
                let elf_found = elf.get_symbols_by_name(name);
                for sym in &elf_found {
                    result.elf_functions.push((elf.clone(), sym.clone()));
                }
            } else {
                result.dwarf_functions.extend(dwarf_found);
            }
        }

        Ok(result)
    }

    pub fn breakpoints(&self) -> &RefCell<StoppointCollection> {
        &self.breakpoints
    }

    pub fn function_name_at_address(&self, address: VirtualAddress) -> Result<String, SdbError> {
        let file_address = address.to_file_addr_elves(&self.elves.borrow());
        let obj = file_address.rc_elf_file();
        let func = obj.get_dwarf().function_containing_address(&file_address)?;
        let elf_filename = obj
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string();
        let mut func_name = String::new();

        if let Some(func) = func
            && let Some(name) = func.name()?
        {
            func_name = name;
        } else {
            let elf_func = obj.get_symbol_containing_file_address(file_address);
            if let Some(elf_func) = elf_func
                && st_type(elf_func.0.st_info) == STT_FUNC
            {
                func_name = obj.get_string(elf_func.0.st_name as usize).to_string();
            }
        }

        if !func_name.is_empty() {
            return Ok(format!("{elf_filename}`{func_name}"));
        }
        Ok(String::new())
    }

    pub fn read_dynamic_linker_rendezvous(&self) -> Result<Option<r_debug>, SdbError> {
        if self.dynamic_linker_rendezvous_address.borrow().addr() != 0 {
            return Ok(Some(self.process.read_memory_as::<r_debug>(
                *self.dynamic_linker_rendezvous_address.borrow(),
            )?));
        }
        Ok(None)
    }

    fn reload_dynamic_libraries(&self) -> Result<(), SdbError> {
        let debug = self.read_dynamic_linker_rendezvous()?;
        if debug.is_none() {
            return Ok(());
        }

        let debug = debug.unwrap();
        let mut entry_ptr = debug.r_map;

        while !entry_ptr.is_null() {
            let entry_addr = VirtualAddress::new(entry_ptr as u64);
            let entry = self
                .process
                .read_memory_as::<super::ffi::link_map>(entry_addr)?;
            entry_ptr = entry.l_next;

            let name_addr = VirtualAddress::new(entry.l_name as u64);
            let name_bytes = self.process.read_memory(name_addr, 4096)?;

            let null_pos = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            let name_str = String::from_utf8_lossy(&name_bytes[..null_pos]);
            let name = PathBuf::from(name_str.as_ref());

            if name_str.is_empty() {
                continue;
            }

            const VDSO_NAME: &str = "linux-vdso.so.1";
            let found = if name_str == VDSO_NAME {
                self.elves.borrow().get_elf_by_filename(VDSO_NAME)
            } else {
                self.elves.borrow().get_elf_by_path(&name)
            };

            if found.upgrade().is_none() {
                let elf_path = if name_str == VDSO_NAME {
                    dump_vdso(&self.process, VirtualAddress::new(entry.l_addr))?
                } else {
                    name
                };

                let new_elf = Elf::new(&elf_path)?;
                new_elf.notify_loaded(VirtualAddress::new(entry.l_addr));
                self.elves.borrow_mut().push(new_elf);
            }
        }

        for bp in self.breakpoints.borrow().iter() {
            bp.borrow_mut().resolve()?;
        }

        Ok(())
    }

    pub fn get_elves(&self) -> &RefCell<ElfCollection> {
        &self.elves
    }

    pub fn get_line_entries_by_line(
        &self,
        path: &Path,
        line: usize,
    ) -> Result<Vec<LineTableIter>, SdbError> {
        let mut entries = Vec::<LineTableIter>::new();
        for elf in self.elves.borrow().iter() {
            for cu in elf.get_dwarf().compile_units() {
                let new_entries = cu.lines().get_entries_by_line(path, line as u64)?;
                entries.extend(new_entries);
            }
        }
        Ok(entries)
    }
}

fn dump_vdso(process: &Process, address: VirtualAddress) -> Result<PathBuf, SdbError> {
    let tmp_dir = "/tmp/sdb-233456".to_string();
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|_| SdbError::new_err("Cannot create temp directory"))?;
    let mut vdso_dump_path = PathBuf::from(tmp_dir);
    vdso_dump_path.push("linux-vdso.so.1");
    let mut vdso_dump = std::fs::File::create(&vdso_dump_path)
        .map_err(|_| SdbError::new_err("Cannot create vdso dump file"))?;
    let vdso_header = process.read_memory_as::<SdbElf64Ehdr>(address)?;
    let vdso_size =
        vdso_header.0.e_shoff + vdso_header.0.e_shentsize as u64 * vdso_header.0.e_shnum as u64;
    let vdso_bytes = process.read_memory(address, vdso_size as usize)?;
    vdso_dump
        .write_all(&vdso_bytes)
        .map_err(|_| SdbError::new_err("Cannot write vdso dump file"))?;
    Ok(vdso_dump_path)
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

    fn resolve_dynamic_linker_rendezvous(&self) -> Result<(), SdbError>;
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

    /*
    void sdb::target::resolve_dynamic_linker_rendezvous() {
        for (auto entry : dynamic_entries) {
            if (entry.d_tag == DT_DEBUG) {
                auto& debug_state_bp = create_address_breakpoint(
                    debug_state_addr, false, true);
                debug_state_bp.install_hit_handler([&] {
                    reload_dynamic_libraries();
                    return true;
                });
                debug_state_bp.enable();
            }
        }
    }
    */
    fn resolve_dynamic_linker_rendezvous(&self) -> Result<(), SdbError> {
        if self.dynamic_linker_rendezvous_address.borrow().addr() != 0 {
            return Ok(());
        }

        let dynamic_section = self
            .main_elf
            .upgrade()
            .unwrap()
            .get_section(".dynamic")
            .unwrap();
        let dynamic_start =
            FileAddress::new(&self.main_elf.upgrade().unwrap(), dynamic_section.0.sh_addr);
        let dynamic_size = dynamic_section.0.sh_size as usize;
        let dynamic_bytes = self
            .process
            .read_memory(dynamic_start.to_virt_addr(), dynamic_size)?;

        let entry_size = std::mem::size_of::<super::ffi::Elf64_Dyn>();
        let num_entries = dynamic_size / entry_size;

        for i in 0..num_entries {
            let start_idx = i * entry_size;
            let end_idx = start_idx + entry_size;
            if end_idx > dynamic_bytes.len() {
                break;
            }

            let entry_bytes = &dynamic_bytes[start_idx..end_idx];
            let entry: super::ffi::Elf64_Dyn =
                unsafe { std::ptr::read(entry_bytes.as_ptr() as *const super::ffi::Elf64_Dyn) };

            if entry.d_tag == super::ffi::DT_DEBUG as i64 {
                let rendezvous_addr = VirtualAddress::new(unsafe { entry.d_un.d_ptr });
                *self.dynamic_linker_rendezvous_address.borrow_mut() = rendezvous_addr;
                self.reload_dynamic_libraries()?;

                let debug_info = self.read_dynamic_linker_rendezvous()?.unwrap();
                let debug_state_addr = VirtualAddress::new(debug_info.r_brk);
                let debug_state_bp =
                    self.create_address_breakpoint(debug_state_addr, false, true)?;
                let debug_state_bp = debug_state_bp.upgrade().unwrap();
                let bp_ref = debug_state_bp.borrow_mut();
                let mut bp = bp_ref as RefMut<dyn std::any::Any>;
                let breakpoint = bp.downcast_mut::<AddressBreakpoint>().unwrap();
                let target_clone = self.clone();
                breakpoint
                    .breakpoint
                    .borrow_mut()
                    .install_hit_handler(move || {
                        target_clone.reload_dynamic_libraries()?;
                        Ok(true)
                    });
                breakpoint.enable()?;
            }
        }

        Ok(())
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
