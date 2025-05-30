use std::path::Path;
use std::rc::Rc;

use nix::unistd::Pid;

use super::elf::Elf;
use super::process::Process;

pub struct Target {
    process: Rc<Process>,
    elf: Rc<Elf>,
}

impl Target {
    fn new(process: &Rc<Process>, elf: &Rc<Elf>) -> Self {
        Self {
            process: process.clone(),
            elf: elf.clone(),
        }
    }

    pub fn launch(path: &Path, out: Option<i32>) -> Rc<Self> {
        todo!()
    }

    pub fn attach(pid: Pid) -> Rc<Self> {
        todo!()
    }

    pub fn get_process(&self) -> Rc<Process> {
        self.process.clone()
    }

    pub fn get_elf(&self) -> Rc<Elf> {
        self.elf.clone()
    }
}
