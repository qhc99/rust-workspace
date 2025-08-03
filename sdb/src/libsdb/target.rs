use std::any::Any;
use std::cell::{RefCell, RefMut};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};

use elf::abi::STT_FUNC;
use gimli::{DW_AT_location, DW_AT_type};
use goblin::elf::sym::st_type;
use nix::libc::{AT_ENTRY, SIGTRAP};
use nix::unistd::Pid;
use typed_builder::TypedBuilder;

use super::traits::FromLowerHexStr;
use super::types::TypedData;

use super::bit::memcpy_bits;

use super::dwarf::DwarfExpressionResult;
use super::dwarf::DwarfExpressionSimpleLocation;
use super::register_info::register_info_by_dwarf;
use super::registers::RegisterValue;

use super::process::ThreadState;

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
    breakpoints: RefCell<StoppointCollection>,
    dynamic_linker_rendezvous_address: RefCell<VirtualAddress>,
    threads: RefCell<HashMap<Pid, SdbThread>>,
}

fn get_initial_variable_data(
    target: &Target,
    name: &str,
    pc: &FileAddress,
) -> Result<TypedData, SdbError> {
    let var = target.find_variable(name, pc)?;
    if var.is_none() {
        return SdbError::err("Variable not found");
    }
    let var = var.unwrap();
    let var_type = var.index(DW_AT_type.0 as u64)?.as_type();
    let loc = var.index(DW_AT_location.0 as u64)?.as_evaluated_location(
        &target.get_process(),
        &target.get_stack(None).borrow().current_frame().registers,
        false,
    )?;
    let data_vec = target.read_location_data(&loc, var_type.byte_size()?, None)?;

    let mut address = None;
    if let DwarfExpressionResult::SimpleLocation(simple_loc) = loc
        && let DwarfExpressionSimpleLocation::Address { address: addr } = simple_loc
    {
        address = Some(addr);
    }
    Ok(TypedData::builder()
        .data(data_vec)
        .type_(var_type)
        .address(address)
        .build())
}

impl Target {
    pub fn resolve_indirect_name(
        &self,
        mut name: &str,
        pc: &FileAddress,
    ) -> Result<TypedData, SdbError> {
        let mut op_pos = name
            .chars()
            .enumerate()
            .find(|(_, c)| *c == '.' || *c == '-' || *c == '[')
            .map(|(i, _)| i);

        let var_name = if let Some(pos) = op_pos {
            &name[..pos]
        } else {
            name
        };

        let mut data = get_initial_variable_data(self, var_name, pc)?;

        while let Some(pos) = op_pos {
            if name.chars().nth(pos).unwrap() == '-' {
                if let Some(p) = name.chars().nth(pos + 1)
                    && p != '>'
                {
                    return SdbError::err("Invalid operator");
                }
                data = data.deref_pointer(&self.get_process())?;
                op_pos = Some(pos + 1);
            }
            if name.chars().nth(op_pos.unwrap()).unwrap() == '.'
                || name.chars().nth(op_pos.unwrap()).unwrap() == '>'
            {
                let member_name_start = op_pos.unwrap() + 1;
                op_pos = name
                    .chars()
                    .enumerate()
                    .skip(member_name_start)
                    .find(|(_, c)| *c == '.' || *c == '-' || *c == '[')
                    .map(|(i, _)| i);
                let member_name = &name[member_name_start..op_pos.unwrap()];
                data = data.read_member(&self.get_process(), member_name)?;
                name = &name[member_name_start..];
            } else if name.chars().nth(op_pos.unwrap()).unwrap() == '[' {
                let int_end = name[op_pos.unwrap()..].find(']').unwrap_or(name.len());
                let index_str = &name[op_pos.unwrap() + 1..int_end];
                let index = usize::from_integral(index_str);
                if index.is_err() {
                    return SdbError::err("Invalid index");
                }
                data = data.index(&self.get_process(), index.unwrap())?;
                name = &name[int_end + 1..];
            }

            op_pos = name
                .chars()
                .enumerate()
                .find(|(_, c)| *c == '.' || *c == '-' || *c == '[')
                .map(|(i, _)| i);
        }

        Ok(data)
    }

    pub fn find_variable(&self, name: &str, pc: &FileAddress) -> Result<Option<Rc<Die>>, SdbError> {
        let dwarf = pc.rc_elf_file().get_dwarf();
        let local = dwarf.find_local_variable(name, pc)?;
        if local.is_some() {
            return Ok(local);
        }

        let mut global = None;
        for elf in self.elves.borrow().iter() {
            let dwarf = elf.get_dwarf();
            let found = dwarf.find_global_variable(name)?;
            if found.is_some() {
                global = found;
            }
        }
        Ok(global)
    }

    pub fn read_location_data(
        &self,
        loc: &DwarfExpressionResult,
        size: usize,
        otid: Option<Pid>, /* None */
    ) -> Result<Vec<u8>, SdbError> {
        let tid = otid.unwrap_or(self.process.current_thread());

        match loc {
            DwarfExpressionResult::SimpleLocation(simple_loc) => match simple_loc {
                DwarfExpressionSimpleLocation::Register { reg_num } => {
                    let reg_info = register_info_by_dwarf(*reg_num as i32)?;
                    let reg_value = self
                        .threads
                        .borrow()
                        .get(&tid)
                        .unwrap()
                        .frames
                        .borrow()
                        .current_frame()
                        .registers
                        .read(&reg_info)?;

                    let get_bytes = |value: RegisterValue| -> Vec<u8> {
                        match value {
                            RegisterValue::U8(v) => vec![v],
                            RegisterValue::U16(v) => v.to_le_bytes().to_vec(),
                            RegisterValue::U32(v) => v.to_le_bytes().to_vec(),
                            RegisterValue::U64(v) => v.to_le_bytes().to_vec(),
                            RegisterValue::I8(v) => (v as u8).to_le_bytes().to_vec(),
                            RegisterValue::I16(v) => (v as u16).to_le_bytes().to_vec(),
                            RegisterValue::I32(v) => (v as u32).to_le_bytes().to_vec(),
                            RegisterValue::I64(v) => (v as u64).to_le_bytes().to_vec(),
                            RegisterValue::Float(v) => v.to_le_bytes().to_vec(),
                            RegisterValue::Double(v) => v.to_le_bytes().to_vec(),
                            RegisterValue::LongDouble(v) => v.0.to_le_bytes().to_vec(),
                            RegisterValue::Byte64(b) => b.to_vec(),
                            RegisterValue::Byte128(b) => b.to_vec(),
                        }
                    };

                    Ok(get_bytes(reg_value))
                }
                DwarfExpressionSimpleLocation::Address { address } => {
                    Ok(self.process.read_memory(*address, size)?)
                }
                DwarfExpressionSimpleLocation::Data { data } => Ok(data.to_vec()),
                DwarfExpressionSimpleLocation::Literal { value } => {
                    let bytes = value.to_le_bytes();
                    Ok(bytes[..size].to_vec())
                }
                DwarfExpressionSimpleLocation::Empty {} => SdbError::err("Empty location"),
            },
            DwarfExpressionResult::Pieces(pieces_res) => {
                let mut data = vec![0u8; size];
                let mut offset = 0usize;

                for piece in &pieces_res.pieces {
                    let byte_size = piece.bit_size.div_ceil(8);
                    let piece_data = self.read_location_data(
                        &DwarfExpressionResult::SimpleLocation(piece.location.clone()),
                        byte_size as usize,
                        otid,
                    )?;

                    if offset % 8 == 0 && piece.offset == 0 && piece.bit_size % 8 == 0 {
                        let dest_byte_offset = offset / 8;
                        let copy_len = piece_data.len().min(data.len() - dest_byte_offset);
                        data[dest_byte_offset..dest_byte_offset + copy_len]
                            .copy_from_slice(&piece_data[..copy_len]);
                        offset += piece.bit_size as usize;
                    } else {
                        memcpy_bits(
                            &mut data,
                            0,
                            &piece_data,
                            piece.offset as u32,
                            piece.bit_size as u32,
                        );
                    }
                }

                Ok(data)
            }
        }
    }

    pub fn threads(&self) -> &RefCell<HashMap<Pid, SdbThread>> {
        &self.threads
    }

    fn new(process: Rc<Process>, elf: Rc<Elf>) -> Rc<Self> {
        Rc::new_cyclic(|weak_self| Self {
            process: process.clone(),
            main_elf: Rc::downgrade(&elf),
            elves: RefCell::new({
                let mut t = ElfCollection::default();
                t.push(elf.clone());
                t
            }),
            breakpoints: RefCell::new(StoppointCollection::default()),
            dynamic_linker_rendezvous_address: RefCell::new(VirtualAddress::default()),
            threads: RefCell::new({
                let threads = process.thread_states();
                let mut ret = HashMap::new();
                for (tid, state) in threads.borrow().iter() {
                    ret.insert(
                        *tid,
                        SdbThread::new(Rc::downgrade(state), Stack::new(weak_self, *tid)),
                    );
                }
                ret
            }),
        })
    }

    pub fn get_stack(&self, otid: Option<Pid>) -> Rc<RefCell<Stack>> {
        let tid = otid.unwrap_or(self.process.current_thread());
        self.threads.borrow().get(&tid).unwrap().frames.clone()
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
        let mut entry_bp = entry_bp as RefMut<dyn Any>;
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

    pub fn notify_stop(&self, reason: &StopReason) -> Result<(), SdbError> {
        self.threads
            .borrow()
            .get(&reason.tid)
            .unwrap()
            .frames
            .borrow_mut()
            .unwind()
    }

    pub fn get_pc_file_address(&self, otid: Option<Pid>) -> FileAddress {
        self.process
            .get_pc(otid)
            .to_file_addr_elves(&self.elves.borrow())
    }

    pub fn step_in(&self, otid: Option<Pid>) -> Result<StopReason, SdbError> {
        let tid = otid.unwrap_or(self.process.current_thread());
        let stack = self.get_stack(Some(tid));
        if stack.borrow().inline_height() > 0 {
            stack.borrow_mut().simulate_inlined_step_in();
            let reason = StopReason::builder()
                .tid(tid)
                .reason(ProcessState::Stopped)
                .info(SIGTRAP)
                .trap_reason(Some(TrapType::SingleStep))
                .build();
            self.threads
                .borrow()
                .get(&tid)
                .unwrap()
                .state
                .upgrade()
                .unwrap()
                .borrow_mut()
                .reason = reason;
            return Ok(reason);
        }
        let orig_line = self.line_entry_at_pc(Some(tid))?;
        loop {
            let reason = self.process.step_instruction(Some(tid))?;
            if !reason.is_step() {
                self.threads
                    .borrow()
                    .get(&tid)
                    .unwrap()
                    .state
                    .upgrade()
                    .unwrap()
                    .borrow_mut()
                    .reason = reason;
                return Ok(reason);
            }
            if !((self.line_entry_at_pc(Some(tid))? == orig_line
                || self.line_entry_at_pc(Some(tid))?.get_current().end_sequence)
                && !self.line_entry_at_pc(Some(tid))?.is_end())
            {
                break;
            }
        }
        let pc = self.get_pc_file_address(Some(tid));
        if pc.has_elf() {
            let dwarf = pc.rc_elf_file().get_dwarf();
            let func = dwarf.function_containing_address(&pc)?;
            if func.is_some() && func.as_ref().unwrap().low_pc()? == pc {
                let mut line = self.line_entry_at_pc(Some(tid))?;
                if !line.is_end() {
                    line.step()?;
                    return self
                        .run_until_address(line.get_current().address.to_virt_addr(), Some(tid));
                }
            }
        }
        Ok(StopReason::builder()
            .tid(tid)
            .reason(ProcessState::Stopped)
            .info(SIGTRAP)
            .trap_reason(Some(TrapType::SingleStep))
            .build())
    }

    pub fn step_out(&self, otid: Option<Pid>) -> Result<StopReason, SdbError> {
        let tid = otid.unwrap_or(self.process.current_thread());
        let stack = self.get_stack(Some(tid));
        let inline_stack = stack.borrow().inline_stack_at_pc()?;
        let has_inline_frames = inline_stack.len() > 1;
        let at_inline_frame = (stack.borrow().inline_height() as usize) < (inline_stack.len() - 1);
        if has_inline_frames && at_inline_frame {
            let current_frame =
                &inline_stack[inline_stack.len() - stack.borrow().inline_height() as usize - 1];
            let return_address = current_frame.high_pc()?.to_virt_addr();
            return self.run_until_address(return_address, Some(tid));
        }

        let return_address = VirtualAddress::new(
            stack.borrow().frames()[stack.borrow().current_frame_index() + 1]
                .registers
                .read_by_id_as::<u64>(RegisterId::rip)?,
        );
        let mut reason = StopReason::builder().build();
        let frames = stack.borrow().frames().len();
        while stack.borrow().frames().len() >= frames {
            reason = self.run_until_address(return_address, Some(tid))?;
            if !reason.is_breakpoint() || self.process.get_pc(None) != return_address {
                return Ok(reason);
            }
        }
        Ok(reason)
    }

    pub fn step_over(&self, otid: Option<Pid>) -> Result<StopReason, SdbError> {
        let tid = otid.unwrap_or(self.process.current_thread());
        let stack = self.get_stack(Some(tid));
        let orig_line = self.line_entry_at_pc(Some(tid))?;
        let disas = Disassembler::new(&self.process);
        let mut reason;
        loop {
            let inline_stack = stack.borrow().inline_stack_at_pc()?;
            let at_start_of_inline_frame = stack.borrow().inline_height() > 0;
            if at_start_of_inline_frame {
                let frame_to_skip =
                    &inline_stack[inline_stack.len() - stack.borrow().inline_height() as usize];
                let return_address = frame_to_skip.high_pc()?.to_virt_addr();
                reason = self.run_until_address(return_address, Some(tid))?;
                if !reason.is_step() || self.process.get_pc(Some(tid)) != return_address {
                    self.threads
                        .borrow()
                        .get(&tid)
                        .unwrap()
                        .state
                        .upgrade()
                        .unwrap()
                        .borrow_mut()
                        .reason = reason;
                    return Ok(reason);
                }
            } else {
                let instructions = disas.disassemble(2, Some(self.process.get_pc(Some(tid))))?;
                if instructions[0].text.rfind("call") == Some(0) {
                    reason = self.run_until_address(instructions[1].address, Some(tid))?;
                    if !reason.is_step()
                        || self.process.get_pc(Some(tid)) != instructions[1].address
                    {
                        self.threads
                            .borrow()
                            .get(&tid)
                            .unwrap()
                            .state
                            .upgrade()
                            .unwrap()
                            .borrow_mut()
                            .reason = reason;
                        return Ok(reason);
                    }
                } else {
                    reason = self.process.step_instruction(Some(tid))?;
                    if !reason.is_step() {
                        self.threads
                            .borrow()
                            .get(&tid)
                            .unwrap()
                            .state
                            .upgrade()
                            .unwrap()
                            .borrow_mut()
                            .reason = reason;
                        return Ok(reason);
                    }
                }
            }

            if !((self.line_entry_at_pc(Some(tid))? == orig_line
                || self.line_entry_at_pc(Some(tid))?.get_current().end_sequence)
                && !self.line_entry_at_pc(Some(tid))?.is_end())
            {
                break;
            }
        }
        Ok(reason)
    }

    pub fn line_entry_at_pc(&self, otid: Option<Pid>) -> Result<LineTableIter, SdbError> {
        let pc = self.get_pc_file_address(otid);
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

    fn run_until_address(
        &self,
        address: VirtualAddress,
        otid: Option<Pid>,
    ) -> Result<StopReason, SdbError> {
        let tid = otid.unwrap_or(self.process.current_thread());
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
        self.process.resume(Some(tid))?;
        let mut reason = self.process.wait_on_signal(tid)?;
        if reason.is_breakpoint() && self.process.get_pc(Some(tid)) == address {
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
        self.threads
            .borrow_mut()
            .get_mut(&tid)
            .unwrap()
            .state
            .upgrade()
            .unwrap()
            .borrow_mut()
            .reason = reason;
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

    fn notify_thread_lifecycle_event(&self, reason: &StopReason);
}

impl TargetExt for Rc<Target> {
    fn notify_thread_lifecycle_event(&self, reason: &StopReason) {
        let tid = reason.tid;
        if reason.reason == ProcessState::Stopped {
            let state = self
                .process
                .thread_states()
                .borrow()
                .get(&tid)
                .unwrap()
                .clone();
            self.threads.borrow_mut().insert(
                tid,
                SdbThread::new(Rc::downgrade(&state), Stack::new(&Rc::downgrade(self), tid)),
            );
        } else {
            self.threads.borrow_mut().remove(&tid);
        }
    }

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

#[derive(TypedBuilder)]
pub struct SdbThread {
    pub state: Weak<RefCell<ThreadState>>,
    pub frames: Rc<RefCell<Stack>>,
}

impl SdbThread {
    pub fn new(state: Weak<RefCell<ThreadState>>, frames: Stack) -> Self {
        Self {
            state,
            frames: Rc::new(RefCell::new(frames)),
        }
    }
}
