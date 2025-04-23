use nix::{
    errno::Errno,
    sys::{
        ptrace::{attach as nix_attach, detach, getregs},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
};

use nix::libc::__errno_location;
use nix::libc::PTRACE_GETFPREGS;
use nix::libc::ptrace;
use nix::{
    sys::ptrace::traceme,
    unistd::{ForkResult, Pid, execvp, fork},
};
use std::{
    cell::{Ref, RefCell, RefMut},
    ffi::CString,
    path::Path,
    process::exit,
    rc::Rc,
};

use super::registers::Registers;

use super::pipe::Pipe;

use super::sdb_error::SdbError;
use super::utils::ResultLogExt;
use nix::sys::ptrace::cont;
use nix::sys::signal::Signal;
use nix::sys::signal::kill;

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
    state: ProcessState,    // Stopped
    is_attached: bool,      // true
    registers: Option<Rc<RefCell<Registers>>>,
}

impl Process {
    fn new(pid: Pid, terminate_on_end: bool, is_attached: bool) -> Rc<RefCell<Self>> {
        let res = Self {
            pid,
            terminate_on_end,
            state: ProcessState::Stopped,
            is_attached,
            registers: None,
        };

        let res = Rc::new(RefCell::new(res));
        res.borrow_mut().registers =
            Some(Rc::new(RefCell::new(Registers::new(Rc::downgrade(&res)))));
        res
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn resume(&mut self) -> Result<(), SdbError> {
        if let Err(errno) = cont(self.pid, None) {
            return SdbError::errno("Could not resume", errno);
        }
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn wait_on_signal(&self) -> Result<StopReason, SdbError> {
        let wait_status = waitpid(self.pid, WaitPidFlag::from_bits(0));
        return match wait_status {
            Err(errno) => SdbError::errno("waitpid failed", errno),
            Ok(status) => Ok(StopReason::new(status)?),
        };
    }

    fn exit_with_error(channel: &Pipe, msg: &str, errno: Errno) -> ! {
        let err_str = errno.desc();
        channel.write(format!("{msg}: {err_str}").as_bytes()).ok();
        exit(-1)
    }

    pub fn launch(
        path: &Path,
        debug: bool, /*true*/
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
            channel.close_read();
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
                    waitpid(pid, WaitPidFlag::from_bits(0)).ok();
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
                0,
                &self.registers.as_deref().unwrap().borrow_mut().data.0.i387,
            ) < 0
            {
                return SdbError::errno(
                    "Could not read FPR registers",
                    Errno::from_raw(*__errno_location()),
                );
            }
        }
        for i in 0..8{
            todo!()
        }
        Ok(())
    }

    pub fn get_registers(&self) -> Ref<'_, Registers> {
        self.registers.as_deref().unwrap().borrow()
    }

    pub fn get_registers_mut(&mut self) -> RefMut<'_, Registers> {
        self.registers.as_deref().unwrap().borrow_mut()
    }

    pub fn read_all_registers() {}
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid.as_raw() != 0 {
            if self.is_attached {
                if self.state == ProcessState::Running {
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
        let proc = super::Process::launch(Path::new("yes"), true);
        assert!(process_exists(proc.unwrap().borrow().pid()));
    }

    #[test]
    fn process_launch_no_such_program() {
        let proc = super::Process::launch(Path::new("you_do_not_have_to_be_good"), true);
        assert!(proc.is_err());
    }
}
