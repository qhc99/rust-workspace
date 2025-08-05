use std::any::Any;
use std::cell::{RefCell, RefMut};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};

use elf::abi::STT_FUNC;
use gimli::{DW_AT_location, DW_AT_object_pointer, DW_AT_type, DW_TAG_subprogram};
use goblin::elf::sym::st_type;
use nix::libc::{AT_ENTRY, SIGTRAP};
use nix::unistd::Pid;
use typed_builder::TypedBuilder;

use super::bit::to_byte_vec;

use super::traits::FromLowerHexStr;
use super::types::BuiltinType;
use super::types::SdbType;
use super::types::TypedData;
use super::types::{read_return_value, setup_arguments};

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
use super::dwarf::LineTableIter;
use super::elf::Elf;
use super::process::Process;
use super::process::StopReason;
use super::process::{ProcessState, TrapType};
use super::register_info::RegisterId;
use super::sdb_error::SdbError;
use super::stack::Stack;
use super::traits::StoppointTrait;
use super::types::FileAddress;
use super::types::VirtualAddress;

pub struct EvaluateExpressionResult {
    pub return_value: TypedData,
    pub id: u64,
}

pub struct Target {
    process: Rc<Process>,
    main_elf: Weak<Elf>,
    elves: RefCell<ElfCollection>,
    breakpoints: RefCell<StoppointCollection>,
    dynamic_linker_rendezvous_address: RefCell<VirtualAddress>,
    threads: RefCell<HashMap<Pid, SdbThread>>,
    expression_results: RefCell<Vec<TypedData>>,
}

fn get_initial_variable_data(
    target: &Target,
    name: &str,
    pc: &FileAddress,
) -> Result<TypedData, SdbError> {
    if let Some(name) = name.strip_prefix('$') {
        let index = usize::from_integral(name);
        if index.is_err() {
            return SdbError::err("Invalid expression result index");
        }
        return target.get_expression_result(index.unwrap());
    }

    let var = target.find_variable(name, pc)?;
    if var.is_none() {
        return SdbError::err("Cannot find variable");
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

pub struct ResolveIndirectNameResult {
    pub variable: Option<TypedData>,
    pub funcs: Vec<Rc<Die>>,
}

impl Target {
    pub fn notify_thread_lifecycle_event(self: &Rc<Self>, reason: &StopReason) {
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

    pub fn create_address_breakpoint(
        self: &Rc<Self>,
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

    pub fn create_function_breakpoint(
        self: &Rc<Self>,
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

    pub fn create_line_breakpoint(
        self: &Rc<Self>,
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

    pub fn resolve_dynamic_linker_rendezvous(self: &Rc<Self>) -> Result<(), SdbError> {
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

    pub fn inferior_malloc(&self, size: usize) -> Result<VirtualAddress, SdbError> {
        let saved_regs = self.process.get_registers(None);

        let malloc_funcs = self.find_functions("malloc")?.elf_functions;
        let malloc_func = malloc_funcs
            .iter()
            .find(|(_, sym)| sym.0.st_value != 0)
            .ok_or_else(|| SdbError::new_err("malloc not found"))?;

        let malloc_addr = FileAddress::new(&malloc_func.0, malloc_func.1.0.st_value);
        let call_addr = malloc_addr.to_virt_addr();

        let entry_point = VirtualAddress::new(self.process.get_auxv()[&(AT_ENTRY as i32)]);
        {
            let breakpoint = self.breakpoints.borrow().get_by_address(entry_point)?;
            let mut breakpoint = breakpoint.borrow_mut() as RefMut<dyn Any>;
            let breakpoint = breakpoint.downcast_mut::<AddressBreakpoint>().unwrap();
            breakpoint
                .breakpoint
                .borrow_mut()
                .install_hit_handler(move || Ok(false));
        }

        self.process.get_registers(None).borrow_mut().write_by_id(
            RegisterId::rdi,
            size as u64,
            true,
        )?;

        #[allow(unused_braces)]
        let new_regs =
            self.process
                .inferior_call(call_addr, entry_point, {saved_regs.borrow().clone()}, None)?;
        let result = new_regs.read_by_id_as::<u64>(RegisterId::rax)?;

        Ok(VirtualAddress::new(result))
    }

    pub fn evaluate_expression(
        &self,
        expr: &str,
        otid: Option<Pid>, /* None */
    ) -> Result<Option<EvaluateExpressionResult>, SdbError> {
        let tid = otid.unwrap_or(self.process.current_thread());
        let pc = self.get_pc_file_address(Some(tid));
        dbg!(expr);
        let paren_pos = expr.find('(');
        if paren_pos.is_none() {
            return SdbError::err("Invalid expression");
        }
        let paren_pos = paren_pos.unwrap();

        let name = &expr[..paren_pos + 1];
        dbg!(name);
        let res = self.resolve_indirect_name(name, &pc)?;
        if res.funcs.is_empty() {
            return SdbError::err("Invalid expression");
        }

        let entry_point = VirtualAddress::new(self.process.get_auxv()[&(AT_ENTRY as i32)]);
        {
            let breakpoint = self.breakpoints.borrow().get_by_address(entry_point)?;
            let mut breakpoint = breakpoint.borrow_mut() as RefMut<dyn Any>;
            let breakpoint = breakpoint.downcast_mut::<AddressBreakpoint>().unwrap();
            breakpoint
                .breakpoint
                .borrow_mut()
                .install_hit_handler(move || Ok(false));
        }

        let arg_string = &expr[paren_pos..];
        let args = collect_arguments(self, tid, arg_string, &res.funcs, res.variable)?;
        let func = resolve_overload(&res.funcs, &args)?;
        let ret = inferior_call_from_dwarf(self, &func, &args, entry_point, tid)?;
        if let Some(ret_data) = ret {
            self.expression_results.borrow_mut().push(ret_data.clone());
            return Ok(Some(EvaluateExpressionResult {
                return_value: ret_data,
                id: (self.expression_results.borrow().len() - 1) as u64,
            }));
        }
        Ok(None)
    }

    pub fn get_expression_result(&self, index: usize) -> Result<TypedData, SdbError> {
        let res = &self.expression_results.borrow()[index];
        let new_data = self
            .process
            .read_memory(res.address().unwrap(), res.value_type().byte_size()?)?;
        Ok(TypedData::builder()
            .data(new_data)
            .type_(res.value_type().clone())
            .address(res.address())
            .build())
    }

    pub fn resolve_indirect_name(
        &self,
        mut name: &str,
        pc: &FileAddress,
    ) -> Result<ResolveIndirectNameResult, SdbError> {
        let mut op_pos = name
            .chars()
            .enumerate()
            .find(|(_, c)| *c == '.' || *c == '-' || *c == '[' || *c == '(')
            .map(|(i, _)| i)
            .or(Some(name.len()));

        if op_pos.unwrap() < name.len() && name.chars().nth(op_pos.unwrap()).unwrap() == '(' {
            let func_name = &name[..op_pos.unwrap()];
            let funcs = self.find_functions(func_name)?;
            return Ok(ResolveIndirectNameResult {
                variable: None,
                funcs: funcs.dwarf_functions,
            });
        }

        let var_name = &name[..op_pos.unwrap()];
        let mut data = get_initial_variable_data(self, var_name, pc)?;
        while let Some(pos) = op_pos
            && pos < name.len()
        {
            if name.chars().nth(pos).unwrap() == '-' {
                if name.chars().nth(pos + 1).map(|c| c != '>').unwrap_or(true) {
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
                    .find(|(_, c)| *c == '.' || *c == '-' || *c == '[' || *c == '(' || *c == ',')
                    .map(|(i, _)| i)
                    .or(Some(name.len()));
                let member_name = &name[member_name_start..op_pos.unwrap()];
                if op_pos.is_some()
                    && op_pos.unwrap() < name.len()
                    && name.chars().nth(op_pos.unwrap()).unwrap() == '('
                {
                    let mut funcs = Vec::new();
                    let stripped_value_type = data.value_type().strip_cvref_typedef()?;
                    for child in stripped_value_type.get_die()?.children() {
                        if child.abbrev_entry().tag as u16 == DW_TAG_subprogram.0
                            && child.contains(DW_AT_object_pointer.0 as u64)
                            && child
                                .name()?
                                .map(|name| name == member_name)
                                .unwrap_or(false)
                        {
                            funcs.push(child);
                        }
                    }
                    if funcs.is_empty() {
                        return SdbError::err("No such member function");
                    }
                    return Ok(ResolveIndirectNameResult {
                        variable: Some(data),
                        funcs,
                    });
                }
                data = data.read_member(&self.get_process(), member_name)?;
                name = &name[member_name_start..];
            } else if name.chars().nth(op_pos.unwrap()).unwrap() == '[' {
                let int_end = name.find(']').unwrap_or(name.len());
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
                .find(|(_, c)| *c == '.' || *c == '-' || *c == '[' || *c == '(' || *c == ',')
                .map(|(i, _)| i)
                .or(Some(name.len()));
        }

        Ok(ResolveIndirectNameResult {
            variable: Some(data),
            funcs: Vec::new(),
        })
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
            expression_results: RefCell::new(Vec::new()),
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

fn parse_argument(target: &Target, tid: Pid, arg: &str) -> Result<TypedData, SdbError> {
    if arg.is_empty() {
        return SdbError::err("Empty argument");
    }
    if arg.len() > 2 && arg.starts_with('"') && arg.ends_with('"') {
        let ptr = target.inferior_malloc(arg.len() - 1)?;
        let arg_str = &arg[1..arg.len() - 1];
        let data_bytes = arg_str.as_bytes();
        let mut data_with_null = data_bytes.to_vec();
        data_with_null.push(0);
        target.process.write_memory(ptr, &data_with_null)?;
        return Ok(TypedData::builder()
            .data(to_byte_vec(&ptr))
            .type_(SdbType::new_builtin(BuiltinType::String))
            .build());
    } else if arg == "true" || arg == "false" {
        let value = arg == "true";
        return Ok(TypedData::builder()
            .data(vec![if value { 1u8 } else { 0u8 }])
            .type_(SdbType::new_builtin(BuiltinType::Boolean))
            .build());
    } else if arg.starts_with('\'') {
        if arg.len() != 3 || !arg.ends_with('\'') {
            return SdbError::err("Invalid character literal");
        }
        let char_byte = arg.chars().nth(1).unwrap() as u8;
        return Ok(TypedData::builder()
            .data(vec![char_byte])
            .type_(SdbType::new_builtin(BuiltinType::Character))
            .build());
    } else if arg.starts_with('-') || arg.chars().next().unwrap().is_ascii_digit() {
        if arg.contains('.') {
            let value: Result<f64, _> = arg.parse();
            dbg!(arg);
            if value.is_err() {
                return SdbError::err("Invalid floating point literal");
            }
            return Ok(TypedData::builder()
                .data(value.unwrap().to_le_bytes().to_vec())
                .type_(SdbType::new_builtin(BuiltinType::FloatingPoint))
                .build());
        } else {
            dbg!(arg);
            let value: Result<i64, _> = arg.parse();
            if value.is_err() {
                return SdbError::err("Invalid integer literal");
            }
            return Ok(TypedData::builder()
                .data(value.unwrap().to_le_bytes().to_vec())
                .type_(SdbType::new_builtin(BuiltinType::Integer))
                .build());
        }
    } else {
        let pc = target.get_pc_file_address(Some(tid));
        let res = target.resolve_indirect_name(arg, &pc)?;
        if !res.funcs.is_empty() {
            return SdbError::err("Nested function calls not supported");
        }
        Ok(res.variable.unwrap())
    }
}

fn collect_arguments(
    target: &Target,
    tid: Pid,
    arg_string: &str,
    funcs: &[Rc<Die>],
    object: Option<TypedData>,
) -> Result<Vec<TypedData>, SdbError> {
    let mut args = Vec::new();
    let proc = target.get_process();

    if let Some(object) = object {
        let data = if let Some(address) = object.address() {
            address.addr().to_le_bytes().to_vec()
        } else {
            let regs = proc.get_registers(Some(tid));
            let mut rsp = regs.borrow().read_by_id_as::<u64>(RegisterId::rsp)?;
            rsp -= object.value_type().byte_size()? as u64;
            proc.write_memory(VirtualAddress::new(rsp), object.data())?;
            regs.borrow_mut().write_by_id(RegisterId::rsp, rsp, true)?;
            rsp.to_le_bytes().to_vec()
        };
        let obj_ptr_die = funcs[0]
            .index(DW_AT_object_pointer.0 as u64)?
            .as_reference();
        let this_type = obj_ptr_die.index(DW_AT_type.0 as u64)?.as_type();
        args.push(TypedData::builder().data(data).type_(this_type).build());
    }

    let mut args_start = 1;
    let args_end = arg_string.find(')').unwrap_or(arg_string.len());

    while args_start < args_end {
        let comma_pos = arg_string
            .chars()
            .enumerate()
            .skip(args_start)
            .find(|(_, c)| *c == ',')
            .map(|(pos, _)| pos)
            .unwrap_or(args_end);
        let arg_expr = &arg_string[args_start..comma_pos];
        args.push(parse_argument(target, tid, arg_expr)?);
        args_start = comma_pos + 1;
    }
    Ok(args)
}

fn resolve_overload(funcs: &[Rc<Die>], args: &[TypedData]) -> Result<Rc<Die>, SdbError> {
    let mut matching_func: Option<Rc<Die>> = None;
    for func in funcs {
        let mut matches = true;
        let params = func.parameter_types()?;

        if args.len() == params.len() {
            for (param_type, arg) in params.iter().zip(args.iter()) {
                if *param_type != *arg.value_type() {
                    matches = false;
                    break;
                }
            }
        } else {
            matches = false;
        }

        if matches {
            if matching_func.is_some() {
                return SdbError::err("Ambiguous function call");
            }
            matching_func = Some(func.clone());
        }
    }

    matching_func.ok_or_else(|| SdbError::new_err("No matching function"))
}

fn inferior_call_from_dwarf(
    target: &Target,
    func: &Rc<Die>,
    args: &[TypedData],
    return_addr: VirtualAddress,
    tid: Pid,
) -> Result<Option<TypedData>, SdbError> {
    let regs = target.get_process().get_registers(Some(tid));
    let saved_regs = regs.borrow().clone();

    let call_addr = if func.contains(gimli::DW_AT_low_pc.0 as u64)
        || func.contains(gimli::DW_AT_ranges.0 as u64)
    {
        func.low_pc()?.to_virt_addr()
    } else {
        let def = func
            .cu()
            .dwarf_info()
            .get_member_function_definition(func)?;
        match def {
            Some(d) => d.low_pc()?.to_virt_addr(),
            None => return SdbError::err("No function definition found"),
        }
    };

    let return_slot = if func.contains(DW_AT_type.0 as u64) {
        let ret_type = func.index(DW_AT_type.0 as u64)?.as_type();
        Some(target.inferior_malloc(ret_type.byte_size()?)?)
    } else {
        None
    };

    setup_arguments(
        target,
        func,
        args.to_vec(),
        &mut regs.borrow_mut(),
        return_slot,
    )?;
    let new_regs =
        target
            .get_process()
            .inferior_call(call_addr, return_addr, saved_regs.clone(), Some(tid))?;

    if func.contains(DW_AT_type.0 as u64) {
        return Ok(Some(read_return_value(
            target,
            func,
            return_slot.unwrap(),
            &new_regs,
        )?));
    }
    Ok(None)
}
