use std::cell::{Ref, RefCell, RefMut};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nix::libc::{AT_ENTRY, SIGTRAP};
use nix::unistd::Pid;

use super::dwarf::LineTableExt;
use super::dwarf::LineTableIter;
use super::elf::Elf;
use super::process::Process;
use super::process::ProcessExt;
use super::process::StopReason;
use super::process::{ProcessState, TrapType};
use super::sdb_error::SdbError;
use super::stack::Stack;
use super::traits::StoppointTrait;
use super::types::FileAddress;
use super::types::VirtualAddress;

pub struct Target {
    process: Rc<Process>,
    elf: Rc<Elf>,
    stack: RefCell<Stack>,
}

impl Target {
    fn new(process: Rc<Process>, elf: Rc<Elf>) -> Rc<Self> {
        Rc::new_cyclic(|weak_self| Self {
            process: process.clone(),
            elf: elf.clone(),
            stack: RefCell::new(Stack::new(&weak_self)),
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
        Ok(tgt)
    }

    pub fn attach(pid: Pid) -> Result<Rc<Self>, SdbError> {
        let elf_path = PathBuf::from("/proc").join(pid.to_string()).join("exe");
        let proc = Process::attach(pid)?;
        let obj = create_loaded_elf(&proc, &elf_path)?;
        let tgt = Target::new(proc, obj);
        tgt.process.set_target(&tgt);
        Ok(tgt)
    }

    pub fn get_process(&self) -> Rc<Process> {
        self.process.clone()
    }

    pub fn get_elf(&self) -> Rc<Elf> {
        self.elf.clone()
    }

    pub fn notify_stop(&self, _reason: &StopReason) -> Result<(), SdbError> {
        self.stack.borrow_mut().reset_inline_height()
    }

    pub fn get_pc_file_address(&self) -> FileAddress {
        self.process.get_pc().to_file_addr(&self.elf)
    }

    pub fn step_in(&self) -> Result<StopReason, SdbError> {
        let stack = self.get_stack();
        if stack.inline_height() > 0 {
            stack.simulate_inlined_step_in();
            return Ok(StopReason::builder()
                .reason(ProcessState::Stopped)
                .info(SIGTRAP)
                .trap_reason(Some(TrapType::SingleStep))
                .build());
        }
        let orig_line = self.get_line_entry_at_pc()?;
        loop {
            let reason = self.process.step_instruction()?;
            if !reason.is_step() {
                return Ok(reason);
            }
            if !((self.get_line_entry_at_pc()? == orig_line
                || self.get_line_entry_at_pc()?.get_current().end_sequence)
                && !self.get_line_entry_at_pc()?.is_end())
            {
                break;
            }
        }
        let pc = self.get_pc_file_address();
        if pc.has_elf() {
            let dwarf = pc.elf_file().get_dwarf();
            let func = dwarf.function_containing_address(&pc)?;
            if func.is_some() && func.as_ref().unwrap().low_pc()? == pc {
                let mut line = self.get_line_entry_at_pc()?;
                if !line.is_end() {
                    line.step()?;
                    return Ok(
                        self.run_until_address(line.get_current().address.to_virtual_address())?
                    );
                }
            }
        }
        Ok(StopReason::builder()
            .reason(ProcessState::Stopped)
            .info(SIGTRAP)
            .trap_reason(Some(TrapType::SingleStep))
            .build())
    }
    pub fn step_out(&self) -> StopReason {
        todo!()
    }
    pub fn step_over(&self) -> StopReason {
        todo!()
    }

    fn get_line_entry_at_pc(&self) -> Result<LineTableIter, SdbError> {
        let pc = self.get_pc_file_address();
        if !pc.has_elf() {
            return Ok(LineTableIter::default());
        }
        let dwarf = pc.elf_file().get_dwarf();
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
                .remove_by_address(breakpoint_to_remove.unwrap().borrow().address())?;
        }
        Ok(reason)
    }
}

fn create_loaded_elf(proc: &Process, path: &Path) -> Result<Rc<Elf>, SdbError> {
    let auxv = proc.get_auxv();
    let obj = Elf::new(path)?;
    obj.notify_loaded(VirtualAddress::new(
        auxv[&(AT_ENTRY as i32)] - obj.get_header().0.e_entry,
    ));
    Ok(obj)
}
