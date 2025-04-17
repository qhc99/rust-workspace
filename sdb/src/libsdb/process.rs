use nix::{
    errno::Errno,
    sys::{
        ptrace::{attach as nix_attach, detach},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
};
use std::{ffi::CString, path::Path};

use nix::{
    sys::ptrace::traceme,
    unistd::{ForkResult, Pid, execvp, fork},
};

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

        SdbError::new("Stopped process returns running state")
    }
}

pub struct Process {
    pid: Pid,
    terminate_on_end: bool, // true
    state: ProcessState,    // Stopped
}

impl Process {
    fn new(pid: Pid, terminate_on_end: bool) -> Self {
        Self {
            pid,
            terminate_on_end,
            state: ProcessState::Stopped,
        }
    }

    pub fn pid(&self) -> Pid {
        Pid::from(self.pid)
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

    fn exit_with_error(pipe: &Pipe, msg: &str, errno: Errno) {}

    pub fn launch(path: &Path) -> Result<Box<Process>, SdbError> {
        let fork_res;
        let channel = Pipe::new(true);
        let mut pid = Pid::from_raw(0);
        unsafe {
            // unsafe in signal handler context
            fork_res = fork();
        }
        let path_str = CString::new(path.to_str().unwrap()).unwrap();
        if let Ok(ForkResult::Child) = fork_res {
            if let Err(errno) = traceme() {
                return SdbError::errno("Tracing failed", errno);
            }
            if execvp(&path_str, &[&path_str]).is_err() {
                eprintln!("Exec failed");
                return SdbError::new("Exec failed");
            }
        } else if let Ok(ForkResult::Parent { child }) = fork_res {
            pid = child;
        } else {
            return SdbError::new("Fork failed");
        }

        let proc = Process::new(pid, true);
        proc.wait_on_signal()?;
        return Ok(Box::new(proc));
    }

    pub fn attach(pid: Pid) -> Result<Box<Process>, SdbError> {
        if pid.as_raw() <= 0 {
            return SdbError::new("Invalid pid");
        }
        if let Err(errno) = nix_attach(pid) {
            return SdbError::errno("Could not attach", errno);
        }
        let proc = Process::new(pid, false);
        proc.wait_on_signal()?;
        return Ok(Box::new(proc));
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid.as_raw() != 0 {
            if self.state == ProcessState::Running {
                kill(self.pid, Signal::SIGSTOP).log_error();
                waitpid(self.pid, WaitPidFlag::from_bits(0)).log_error();
            }
            detach(self.pid, None).log_error();
            kill(self.pid, Signal::SIGCONT).log_error();
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
    fn launch_success() {
        let proc = super::Process::launch(Path::new("yes"));
        assert!(process_exists(proc.unwrap().pid()));
    }

    #[test]
    fn launch_no_such_program() {
        let proc = super::Process::launch(Path::new("you_do_not_have_to_be_good"));
        assert!(proc.is_err());
    }
}
