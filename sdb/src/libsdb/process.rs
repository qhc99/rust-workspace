use super::breakpoint_site::BreakpointSite;
use super::pipe::Pipe;
use super::register_info::RegisterId;
use super::register_info::register_info_by_id;
use super::registers::Registers;
use super::sdb_error::SdbError;
use super::stoppoint_collection::StoppointCollection;
use super::traits::StoppointTrait;
use super::types::VirtualAddress;
use super::utils::ResultLogExt;
use nix::libc::PTRACE_GETFPREGS;
use nix::libc::ptrace;
use nix::sys::personality::Persona;
use nix::sys::personality::set as set_personality;
use nix::sys::ptrace::AddressType;
use nix::sys::ptrace::cont;
use nix::sys::ptrace::step;
use nix::sys::signal::Signal;
use nix::sys::signal::kill;
use nix::unistd::dup2;
use nix::{
    errno::Errno,
    libc::{PTRACE_SETFPREGS, PTRACE_SETREGS, user_fpregs_struct, user_regs_struct},
    sys::{
        ptrace::{attach as nix_attach, detach, getregs, read_user, write_user},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
};
use nix::{
    sys::ptrace::traceme,
    unistd::{ForkResult, Pid, execvp, fork},
};
use std::os::fd::AsRawFd;
use std::{cell::RefCell, ffi::CString, os::raw::c_void, path::Path, process::exit, rc::Rc};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Stopped,
    Running,
    Exited,
    Terminated,
}

pub struct StopReason {
    pub reason: ProcessState,
    pub info: i32,
}

impl StopReason {
    fn new(status: WaitStatus) -> Result<Self, SdbError> {
        if let WaitStatus::Exited(_, info) = status {
            return Ok(StopReason {
                reason: ProcessState::Exited,
                info,
            });
        } else if let WaitStatus::Signaled(_, info, _) = status {
            return Ok(StopReason {
                reason: ProcessState::Terminated,
                info: info as i32,
            });
        } else if let WaitStatus::Stopped(_, info) = status {
            return Ok(StopReason {
                reason: ProcessState::Stopped,
                info: info as i32,
            });
        }

        SdbError::err("Stopped process returns running state")
    }
}

pub struct Process {
    pid: Pid,
    terminate_on_end: bool, // true
    // Use RefCell to avoid mut borrow runtime error 
    state: RefCell<ProcessState>,    // Stopped
    is_attached: bool,      // true
    registers: Option<Rc<RefCell<Registers>>>,
    breakpoint_sites: Rc<RefCell<StoppointCollection<BreakpointSite>>>,
}

impl Process {
    fn new(pid: Pid, terminate_on_end: bool, is_attached: bool) -> Rc<RefCell<Self>> {
        let res = Self {
            pid,
            terminate_on_end,
            state: RefCell::new(ProcessState::Stopped),
            is_attached,
            registers: None,
            breakpoint_sites: Rc::new(RefCell::new(StoppointCollection::default())),
        };

        let res = Rc::new(RefCell::new(res));
        res.borrow_mut().registers = Some(Rc::new(RefCell::new(Registers::new(&res))));
        res
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn resume(&self) -> Result<(), SdbError> {
        let pc = self.get_pc();
        if self
            .breakpoint_sites
            .borrow()
            .enabled_breakpoint_at_address(pc)
        {
            let bp = self.breakpoint_sites.borrow().get_by_address(pc)?;
            bp.borrow_mut().disable()?;
            step(self.pid, None)
                .map_err(|errno| SdbError::new_errno("Failed to single step", errno))?;
            waitpid(self.pid, None)
                .map_err(|errno| SdbError::new_errno("Waitpid failed", errno))?;
            bp.borrow_mut().enable()?;
        }
        if let Err(errno) = cont(self.pid, None) {
            return SdbError::errno("Could not resume", errno);
        }
        *self.state.borrow_mut() = ProcessState::Running;
        Ok(())
    }

    pub fn state(&self) -> ProcessState {
        self.state.borrow().clone()
    }

    pub fn wait_on_signal(&self) -> Result<StopReason, SdbError> {
        let wait_status = waitpid(self.pid, WaitPidFlag::from_bits(0));
        return match wait_status {
            Err(errno) => SdbError::errno("waitpid failed", errno),
            Ok(status) => {
                let reason = StopReason::new(status)?;
                *self.state.borrow_mut() = reason.reason;

                if self.is_attached && self.state.borrow().clone() == ProcessState::Stopped {
                    self.read_all_registers()?;
                    let instr_begin = self.get_pc() - 1;
                    if reason.info == Signal::SIGTRAP as i32
                        && self
                            .breakpoint_sites
                            .borrow()
                            .enabled_breakpoint_at_address(instr_begin)
                    {
                        self.set_pc(instr_begin)?;
                    }
                }
                Ok(reason)
            }
        };
    }

    fn exit_with_error(channel: &Pipe, msg: &str, errno: Errno) -> ! {
        let err_str = errno.desc();
        channel
            .write(format!("{msg}: {err_str}").as_bytes())
            .unwrap();
        exit(-1)
    }

    pub fn launch(
        path: &Path,
        debug: bool, /*true*/
        stdout_replacement: Option<i32>,
    ) -> Result<Rc<RefCell<Process>>, SdbError> {
        let fork_res;
        let mut channel = Pipe::new(true)?;
        let mut pid = Pid::from_raw(0);
        unsafe {
            // unsafe in signal handler context
            fork_res = fork();
        }
        let path_str = CString::new(path.to_str().unwrap()).unwrap();
        if let Ok(ForkResult::Child) = fork_res {
            let res = set_personality(Persona::ADDR_NO_RANDOMIZE);
            if let Err(errno) = res {
                Process::exit_with_error(&channel, "Subprocess set peronality failed", errno);
            }
            channel.close_read();
            if let Some(fd) = stdout_replacement {
                if let Err(errno) = dup2(fd, std::io::stdout().as_raw_fd()) {
                    Process::exit_with_error(&channel, "Stdout replacement failed", errno);
                }
            }
            if debug {
                if let Err(errno) = traceme() {
                    Process::exit_with_error(&channel, "Tracing failed", errno);
                }
            }
            if execvp(&path_str, &[&path_str]).is_err() {
                Process::exit_with_error(&channel, "Exec failed", Errno::from_raw(0));
            }
        } else if let Ok(ForkResult::Parent { child }) = fork_res {
            pid = child;
            channel.close_write();
            let data = channel.read();
            channel.close_read();
            if let Ok(msg) = data {
                if !msg.is_empty() {
                    waitpid(pid, WaitPidFlag::from_bits(0)).map_err(|errno| {
                        SdbError::new_err(&format!("Waitpid child failed, errno: {errno}"))
                    })?;
                    return SdbError::err(std::str::from_utf8(&msg).unwrap());
                }
            }
        } else {
            return SdbError::err("Fork failed");
        }

        let proc = Process::new(pid, true, debug);
        if debug {
            proc.borrow().wait_on_signal()?;
        }
        return Ok(proc);
    }

    pub fn attach(pid: Pid) -> Result<Rc<RefCell<Process>>, SdbError> {
        if pid.as_raw() <= 0 {
            return SdbError::err("Invalid pid");
        }
        if let Err(errno) = nix_attach(pid) {
            return SdbError::errno("Could not attach", errno);
        }
        let proc = Process::new(pid, false, true);
        proc.borrow().wait_on_signal()?;
        return Ok(proc);
    }

    pub fn write_user_area(&self, offset: usize, data: u64) -> Result<(), SdbError> {
        match write_user(self.pid, offset as AddressType, data.try_into().unwrap()) {
            Ok(_) => Ok(()),
            Err(errno) => SdbError::errno("Could not write user area", errno),
        }
    }

    pub fn get_registers(&self) -> Rc<RefCell<Registers>> {
        self.registers.clone().unwrap()
    }

    pub fn read_all_registers(&self) -> Result<(), SdbError> {
        let regs = getregs(self.pid);
        match regs {
            Ok(data) => {
                self.registers.as_deref().unwrap().borrow_mut().data.0.regs = data;
                Ok(())
            }
            Err(errno) => SdbError::errno("Could not read GPR registers", errno),
        }?;

        unsafe {
            if ptrace(
                PTRACE_GETFPREGS,
                self.pid,
                std::ptr::null_mut::<c_void>(),
                &mut self.registers.as_deref().unwrap().borrow_mut().data.0.i387 as *mut _
                    as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not read FPR registers", Errno::last());
            }
        }
        for i in 0..8 {
            let id = RegisterId::dr0 as i32 + i;
            let info = register_info_by_id(RegisterId::try_from(id).unwrap())?;

            match read_user(self.pid, info.offset as *mut c_void) {
                Ok(data) => {
                    self.registers
                        .as_deref()
                        .unwrap()
                        .borrow_mut()
                        .data
                        .0
                        .u_debugreg[i as usize] = data as u64;
                }
                Err(errno) => SdbError::errno("Could not read debug register", errno)?,
            };
        }

        Ok(())
    }

    pub fn write_gprs(&self, gprs: &mut user_regs_struct) -> Result<(), SdbError> {
        unsafe {
            if ptrace(
                PTRACE_SETREGS,
                self.pid,
                std::ptr::null_mut::<c_void>(),
                gprs as *mut _ as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not write GPR registers", Errno::last());
            }
            Ok(())
        }
    }

    pub fn write_fprs(&self, fprs: &mut user_fpregs_struct) -> Result<(), SdbError> {
        unsafe {
            if ptrace(
                PTRACE_SETFPREGS,
                self.pid,
                std::ptr::null_mut::<c_void>(),
                fprs as *mut _ as *mut c_void,
            ) < 0
            {
                return SdbError::errno("Could not write FPR registers", Errno::last());
            }
            Ok(())
        }
    }

    pub fn get_pc(&self) -> VirtualAddress {
        self.get_registers()
            .borrow()
            .read_by_id_as::<u64>(RegisterId::rip)
            .unwrap()
            .into()
    }

    pub fn breakpoint_sites(&self) -> Rc<RefCell<StoppointCollection<BreakpointSite>>> {
        self.breakpoint_sites.clone()
    }

    pub fn set_pc(&self, address: VirtualAddress) -> Result<(), SdbError> {
        self.get_registers()
            .borrow_mut()
            .write_by_id(RegisterId::rip, address.get_addr())?;
        Ok(())
    }
}

pub trait ProcessExt {
    fn create_breakpoint_site(
        &self,
        address: VirtualAddress,
    ) -> Result<Rc<RefCell<BreakpointSite>>, SdbError>;
}

impl ProcessExt for Rc<RefCell<Process>> {
    fn create_breakpoint_site(
        &self,
        address: VirtualAddress,
    ) -> Result<Rc<RefCell<BreakpointSite>>, SdbError> {
        if self
            .borrow()
            .breakpoint_sites
            .borrow()
            .contain_address(address)
        {
            return SdbError::err(&format!(
                "Breakpoint site already created at address {}",
                address.get_addr()
            ));
        }
        Ok(self
            .borrow()
            .breakpoint_sites
            .borrow_mut()
            .push(BreakpointSite::new(self, address)))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid.as_raw() != 0 {
            if self.is_attached {
                if self.state.borrow().clone() == ProcessState::Running {
                    kill(self.pid, Signal::SIGSTOP).log_error();
                    waitpid(self.pid, WaitPidFlag::from_bits(0)).log_error();
                }
                detach(self.pid, None).log_error();
                kill(self.pid, Signal::SIGCONT).log_error();
            }
            if self.terminate_on_end {
                kill(self.pid, Signal::SIGKILL).log_error();
                waitpid(self.pid, WaitPidFlag::from_bits(0)).log_error();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    use std::path::Path;

    fn process_exists(pid: Pid) -> bool {
        return kill(pid, None).is_ok();
    }

    #[test]
    fn process_launch_success() {
        let proc = super::Process::launch(Path::new("yes"), true, None);
        assert!(process_exists(proc.unwrap().borrow().pid()));
    }

    #[test]
    fn process_launch_no_such_program() {
        let proc = super::Process::launch(Path::new("you_do_not_have_to_be_good"), true, None);
        assert!(proc.is_err());
    }
}
