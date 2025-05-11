use super::sdb_error::SdbError;

use super::process::Process;
use super::types::VirtualAddress;
use std::{
    cell::RefCell,
    rc::{Rc, Weak},
};
use zydis::{Decoder, Formatter, VisibleOperands};
use zydis_sys::ZyanUSize;

pub struct Disassembler {
    process: Weak<RefCell<Process>>,
}

pub struct Instruction {
    pub address: VirtualAddress,
    pub text: String,
}

impl Disassembler {
    pub fn new(process: &Rc<RefCell<Process>>) -> Self {
        Self {
            process: Rc::downgrade(process),
        }
    }

    pub fn disassemble(
        &self,
        mut n_instructions: usize,
        mut address: Option<VirtualAddress>, /*None*/
    ) -> Result<Vec<Instruction>, SdbError> {
        let mut ret = Vec::<Instruction>::with_capacity(n_instructions);
        let owned_process = self.process.upgrade().unwrap();
        let process = owned_process.borrow();
        if address.is_none() {
            address = Some(process.get_pc());
        }
        let mut address = address.unwrap();
        let code = process.read_memory(address, n_instructions * 15)?;
        let mut offset: ZyanUSize = 0;

        let decoder = Decoder::new64();
        let formatter = Formatter::att();
        while n_instructions > 0 && (offset as usize) < code.len() {
            match decoder.decode_first::<VisibleOperands>(&code[offset as usize..]) {
                Ok(Some(insn)) => {
                    let text = formatter.format(Some(offset), &insn).unwrap();
                    ret.push(Instruction { address, text });
                    offset += insn.length as u64;
                    address += insn.length as i64;
                    n_instructions -= 1;
                }
                _ => break,
            }
        }
        Ok(ret)
    }
}

pub fn print_disassembly(
    process: &Rc<RefCell<Process>>,
    address: VirtualAddress,
    n_instructions: usize,
) -> Result<(), SdbError> {
    let dis = Disassembler::new(process);
    let instructions = dis.disassemble(n_instructions, Some(address))?;
    for inst in instructions {
        println!("{:#018x}: {}", inst.address, inst.text);
    }
    Ok(())
}
