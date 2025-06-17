use std::path::{Path, PathBuf};
use std::rc::Rc;

use nix::libc::AT_ENTRY;
use nix::unistd::Pid;

use super::elf::Elf;
use super::process::Process;
use super::process::StopReason;
use super::sdb_error::SdbError;
use super::types::VirtualAddress;

pub struct Target {
    process: Rc<Process>,
    elf: Rc<Elf>,
}

impl Target {
    fn new(process: Rc<Process>, elf: Rc<Elf>) -> Self {
        Self {
            process: process.clone(),
            elf: elf.clone(),
        }
    }

    pub fn launch(path: &Path, stdout_replacement: Option<i32>) -> Result<Rc<Self>, SdbError> {
        let proc = Process::launch(path, true, stdout_replacement)?;
        let obj = create_loaded_elf(&proc, path)?;
        let tgt = Rc::new(Target::new(proc, obj));
        tgt.process.set_target(&tgt);
        Ok(tgt)
    }

    pub fn attach(pid: Pid) -> Result<Rc<Self>, SdbError> {
        let elf_path = PathBuf::from("/proc").join(pid.to_string()).join("exe");
        let proc = Process::attach(pid)?;
        let obj = create_loaded_elf(&proc, &elf_path)?;
        let tgt = Rc::new(Target::new(proc, obj));
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
}

fn create_loaded_elf(proc: &Process, path: &Path) -> Result<Rc<Elf>, SdbError> {
    let auxv = proc.get_auxv();
    let obj = Elf::new(path)?;
    obj.notify_loaded(VirtualAddress::new(
        auxv[&(AT_ENTRY as i32)] - obj.get_header().0.e_entry,
    ));
    Ok(obj)
}
