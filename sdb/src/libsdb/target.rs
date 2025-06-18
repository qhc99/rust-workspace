use std::cell::{Ref, RefCell, RefMut};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nix::libc::AT_ENTRY;
use nix::unistd::Pid;

use super::stack::Stack;

use super::types::FileAddress;

use super::elf::Elf;
use super::process::Process;
use super::process::StopReason;
use super::sdb_error::SdbError;
use super::types::VirtualAddress;

pub struct Target {
    process: Rc<Process>,
    elf: Rc<Elf>,
    stack: RefCell<Stack>,
}

impl Target {
    fn new(process: Rc<Process>, elf: Rc<Elf>) -> Rc<Self> {
        Rc::new_cyclic(|weak_self| {
            Self {
                process: process.clone(),
                elf:     elf.clone(),
                stack:   RefCell::new(Stack::new(&weak_self)),
            }
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

    pub fn notify_stop(&self, reason: &StopReason) {
        todo!()
    }

    pub fn get_pc_file_address(&self) -> FileAddress {
        self.process.get_pc().to_file_addr(&self.elf)
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
