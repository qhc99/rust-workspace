use nix::sys::ptrace::attach as nix_attach;
use std::{ffi::CString, path::Path};

use nix::{
    sys::ptrace::traceme,
    unistd::{ForkResult, Pid, execvp, fork},
};

use super::sdb_error::SdbError;

#[derive(Clone, Copy)]
enum ProcessState {
    Stopped,
    Running,
    Exited,
    Terminated,
}
struct Process {
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

    pub fn resume(&self) {}

    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn wait_on_signal(&self) {}

    pub fn launch(path: &Path) -> Result<Box<Process>, SdbError> {
        let fork_res;
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
                return SdbError::new("Exec failed");
            }
        } else if let Ok(ForkResult::Parent { child }) = fork_res {
            pid = child;
        } else {
            return SdbError::new("Fork failed");
        }

        let proc = Process::new(pid, true);
        proc.wait_on_signal();
        return Ok(Box::new(proc));
    }

    pub fn attach(pid: Pid) -> Result<Box<Process>, SdbError> {
        if pid <= Pid::from_raw(0) {
            return SdbError::new("Invalid pid");
        }
        if let Err(errno) = nix_attach(pid) {
            return SdbError::errno("Could not attach", errno);
        }
        let proc = Process::new(pid, false);
        proc.wait_on_signal();
        return Ok(Box::new(proc));
    }
}
