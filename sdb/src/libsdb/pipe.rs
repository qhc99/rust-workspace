use super::sdb_error::SdbError;
use nix::fcntl::OFlag;
use nix::unistd::pipe2;
use nix::unistd::read;
use nix::unistd::write;
use std::os::fd::{AsRawFd, OwnedFd};

#[derive(Debug)]
pub struct Pipe {
    fds: [Option<OwnedFd>; 2],
}

impl Pipe {
    pub const READ_FD: usize = 0;
    pub const WRITE_FD: usize = 1;

    pub fn new(close_on_exec: bool) -> Result<Self, SdbError> {
        match pipe2(if close_on_exec {
            OFlag::O_CLOEXEC
        } else {
            OFlag::from_bits(0).unwrap()
        }) {
            Ok((read, write)) => Ok(Pipe {
                fds: [Some(read), Some(write)],
            }),
            Err(errno) => SdbError::errno("Pipe creation failed", errno),
        }
    }

    pub fn get_read_fd(&self) -> i32 {
        self.fds[Pipe::READ_FD].as_ref().unwrap().as_raw_fd()
    }

    pub fn get_write_fd(&self) -> i32 {
        self.fds[Pipe::WRITE_FD].as_ref().unwrap().as_raw_fd()
    }

    pub fn release_read(&mut self) -> OwnedFd {
        let fd = self.fds[Pipe::READ_FD].take();
        return fd.unwrap();
    }
    pub fn release_write(&mut self) -> OwnedFd {
        let fd = self.fds[Pipe::WRITE_FD].take();
        return fd.unwrap();
    }

    pub fn close_read(&mut self) {
        self.release_read();
    }
    pub fn close_write(&mut self) {
        self.release_write();
    }

    pub fn read(&self) -> Result<Vec<u8>, SdbError> {
        let buf: &mut [u8] = &mut [0u8; 1024];
        match read(self.fds[Pipe::READ_FD].as_ref().unwrap().as_raw_fd(), buf) {
            Ok(size) => Ok(buf[..size].to_vec()),
            Err(errno) => SdbError::errno("Could not read from pipe", errno),
        }
    }

    pub fn write(&self, bytes: &[u8]) -> Result<(), SdbError> {
        match write(self.fds[Pipe::WRITE_FD].as_ref().unwrap(), bytes) {
            Ok(_) => Ok(()),
            Err(errno) => SdbError::errno("Could not read from pipe", errno),
        }
    }
}
