use super::{dwarf::Die, sdb_error::SdbError};
use std::rc::{Rc, Weak};

use super::target::Target;

pub struct Stack {
    target: Weak<Target>,
    inline_height: u32,   // 0
}

impl Stack {
    pub fn new(target: &Weak<Target>) -> Self {
        Self {
            target: target.clone(),
            inline_height: 0,
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
        return pc.elf_file().get_dwarf().inline_stack_at_address(&pc);
    }

    pub fn inline_height(&self) -> u32 {
        self.inline_height
    }

    pub fn get_target(&self) -> Rc<Target> {
        self.target.upgrade().unwrap()
    }

    pub fn simulate_inlined_step_in(&self) {
        todo!()
    }
}
