use super::sdb_error::SdbError;

use super::process::Process;
use super::types::VirtualAddress;
use std::cell::Ref;
use zydis::{Decoder, Formatter, VisibleOperands};
use zydis_sys::ZyanUSize;

pub struct Disassembler<'this> {
    process: &'this Process,
}

pub struct Instruction {
    pub address: VirtualAddress,
    pub text: String,
}

impl<'this> Disassembler<'this> {
    pub fn new(process: &'this Process) -> Self {
        Self { process }
    }

    pub fn disassemble(
        &self,
        mut n_instructions: usize,
        mut address: Option<VirtualAddress>, /*None*/
    ) -> Result<Vec<Instruction>, SdbError> {
        let mut ret = Vec::<Instruction>::with_capacity(n_instructions);
        if address.is_none() {
            address = Some(self.process.get_pc());
        }
        let mut address = address.unwrap();
        let code = self
            .process
            .read_memory_without_trap(address, n_instructions * 15)?;
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
    process: &Ref<Process>,
    address: VirtualAddress,
    n_instructions: usize,
) -> Result<(), SdbError> {
    let dis = Disassembler::new(&process);
    let instructions = dis.disassemble(n_instructions, Some(address))?;
    for inst in instructions {
        println!("{:#018x}: {}", inst.address, inst.text);
    }
    Ok(())
}
