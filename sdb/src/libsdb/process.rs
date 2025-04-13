use nix::unistd::Pid;

struct Process {
    pid: Pid,
}

impl Process {
    pub fn pid(&self) -> Pid {
        Pid::from(self.pid)
    }

    pub fn resume(){
        
    }
}
