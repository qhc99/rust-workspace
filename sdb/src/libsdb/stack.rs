use super::register_info::RegisterId;
use super::types::FileAddress;
use super::{dwarf::Die, sdb_error::SdbError};
use super::{dwarf::SourceLocation, registers::Registers, types::VirtualAddress};
use std::cell::RefCell;
use std::rc::{Rc, Weak};

use super::target::Target;

pub struct Stack {
    target: Weak<Target>,
    inline_height: u32, // 0
    frames: Vec<StackFrame>,
    current_frame: usize, /* 0 */
}

impl Stack {
    pub fn new(target: &Weak<Target>) -> Self {
        Self {
            target: target.clone(),
            inline_height: 0,
            frames: Vec::new(),
            current_frame: 0,
        }
    }

    pub fn reset_inline_height(&mut self) -> Result<(), SdbError> {
        let stack = self.inline_stack_at_pc()?;
        self.inline_height = 0;
        let pc = self.get_target().get_pc_file_address();
        for it in stack.iter().rev() {
            if it.low_pc()? == pc {
                self.inline_height += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    pub fn inline_stack_at_pc(&self) -> Result<Vec<Rc<Die>>, SdbError> {
        let pc = self.get_target().get_pc_file_address();
        if !pc.has_elf() {
            return Ok(vec![]);
        }
        return pc.rc_elf_file().get_dwarf().inline_stack_at_address(&pc);
    }

    pub fn inline_height(&self) -> u32 {
        self.inline_height
    }

    pub fn get_target(&self) -> Rc<Target> {
        self.target.upgrade().unwrap()
    }

    pub fn simulate_inlined_step_in(&mut self) {
        self.inline_height -= 1;
        self.current_frame = self.inline_height as usize;
    }

    pub fn unwind(&mut self) -> Result<(), SdbError> {
        self.reset_inline_height()?;
        self.current_frame = self.inline_height as usize;
        let target = self.get_target();
        let mut virt_pc = target.get_process().get_pc();
        let mut file_pc = target.get_pc_file_address();
        let proc = target.get_process();
        let mut regs = proc.get_registers();

        self.frames.clear();
        if !file_pc.has_elf() {
            return Ok(());
        }
        let mut elf = file_pc.weak_elf_file();
        while virt_pc.addr() != 0 && elf.upgrade().is_some() && Rc::ptr_eq(&elf.upgrade().unwrap(), &target.get_elf()) {
            let dwarf = elf.upgrade().unwrap().get_dwarf();
            let inline_stack = dwarf.inline_stack_at_address(&file_pc)?;
            if inline_stack.is_empty() {
                return Ok(());
            }
            if inline_stack.len() > 1 {
                self.create_base_frame(
                    &regs.borrow(),
                    inline_stack.clone(),
                    file_pc.clone(),
                    true,
                )?;
                self.create_inline_stack_frames(
                    &regs.borrow(),
                    inline_stack.clone(),
                    file_pc.clone(),
                )?;
            } else {
                self.create_base_frame(
                    &regs.borrow(),
                    inline_stack.clone(),
                    file_pc.clone(),
                    false,
                )?;
            }
            regs = Rc::new(RefCell::new(dwarf.cfi().borrow_mut().unwind(
                &proc,
                file_pc,
                &mut self.frames.last_mut().unwrap().registers,
            )?));
            virt_pc = VirtualAddress::new(regs.borrow().read_by_id_as::<u64>(RegisterId::rip)? - 1);
            file_pc = virt_pc.to_file_addr(&elf.upgrade().unwrap());
            elf = file_pc.weak_elf_file();
        }
        Ok(())
    }

    pub fn up(&mut self) {
        self.current_frame += 1;
    }

    pub fn down(&mut self) {
        self.current_frame -= 1;
    }

    pub fn frames(&self) -> &[StackFrame] {
        &self.frames[self.inline_height as usize..]
    }

    pub fn has_frames(&self) -> bool {
        !self.frames.is_empty()
    }

    pub fn current_frame(&self) -> &StackFrame {
        &self.frames[self.current_frame]
    }

    pub fn current_frame_index(&self) -> usize {
        self.current_frame - self.inline_height as usize
    }

    pub fn regs(&self) -> &Registers {
        &self.current_frame().registers
    }

    pub fn get_pc(&self) -> Result<VirtualAddress, SdbError> {
        Ok(VirtualAddress::new(
            self.regs().read_by_id_as::<u64>(RegisterId::rip)?,
        ))
    }

    fn create_inline_stack_frames(
        &mut self,
        regs: &Registers,
        inline_stack: Vec<Rc<Die>>,
        _pc: FileAddress,
    ) -> Result<(), SdbError> {
        let mut prev_it = inline_stack.last().unwrap().clone();
        for (i, it) in inline_stack.iter().rev().enumerate().skip(1) {
            let inlined_pc = prev_it.low_pc()?.to_virt_addr();
            self.frames.push(StackFrame {
                registers: regs.clone(),
                backtrace_report_address: inlined_pc,
                func_die: it.as_ref().clone(),
                inlined: i +1 != inline_stack.len(),
                source_location: prev_it.location()?,
            });
            prev_it = it.clone();
        }
        Ok(())
    }

    fn create_base_frame(
        &mut self,
        regs: &Registers,
        inline_stack: Vec<Rc<Die>>,
        pc: FileAddress,
        inlined: bool,
    ) -> Result<(), SdbError> {
        let mut backtrace_pc = pc.to_virt_addr();
        let line_entry = pc.rc_elf_file().get_dwarf().line_entry_at_address(&pc)?;
        if !line_entry.is_end() {
            backtrace_pc = line_entry.get_current().address.to_virt_addr();
        }

        self.frames.push(StackFrame {
            registers: regs.clone(),
            backtrace_report_address: backtrace_pc,
            func_die: (*inline_stack.last().unwrap().as_ref()).clone(),
            inlined,
            source_location: SourceLocation {
                file: line_entry
                    .get_current()
                    .file_entry
                    .as_ref()
                    .unwrap()
                    .clone(),
                line: line_entry.get_current().line.clone(),
            },
        });
        Ok(())
    }
}

pub struct StackFrame {
    pub registers: Registers,
    pub backtrace_report_address: VirtualAddress,
    pub func_die: Die,
    pub inlined: bool, /* false */
    pub source_location: SourceLocation,
}
