use std::{error::Error, fmt::Display};

use nix::errno::Errno;

#[derive(Debug)]
pub struct SdbError {
    details: String,
    errno: Errno,
}

impl Error for SdbError {}

impl SdbError {
    pub fn new<T>(s: &str) -> Result<T, SdbError> {
        Err(SdbError {
            details: s.to_owned(),
            errno: Errno::UnknownErrno,
        })
    }

    pub fn errno<T>(s: &str, errno: Errno) -> Result<T, SdbError> {
        Err(SdbError {
            details: s.to_owned(),
            errno,
        })
    }
}

impl Display for SdbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errno == Errno::UnknownErrno {
            write!(f, "{}", self.details)
        } else {
            write!(
                f,
                "{}: {} (errno {})",
                self.details,
                self.errno.desc(),
                self.errno
            )
        }
    }
}
