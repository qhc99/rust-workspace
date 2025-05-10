use nix::errno::Errno;
use std::{error::Error, fmt::Display};
use std::backtrace::Backtrace;
#[derive(Debug)]
pub struct SdbError {
    details: String,
    errno: Errno,
    backtrace: Backtrace,
}

impl SdbError {
    pub fn err<T>(s: &str) -> Result<T, SdbError> {
        Err(SdbError::new_err(s))
    }

    pub fn new_err(s: &str) -> SdbError {
        SdbError {
            details: s.to_owned(),
            errno: Errno::UnknownErrno,
             backtrace: Backtrace::capture(),
        }
    }

    pub fn new_errno(s: &str, errno: Errno) -> SdbError {
        SdbError {
            details: s.to_owned(),
            errno,
             backtrace: Backtrace::capture(),
        }
    }

    pub fn errno<T>(s: &str, errno: Errno) -> Result<T, SdbError> {
        Err(SdbError::new_errno(s, errno))
    }
}

impl Error for SdbError {}

impl Display for SdbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errno == Errno::UnknownErrno {
            write!(f, "{}", self.details)?;
        } else {
            write!(
                f,
                "{}: {} (errno {})",
                self.details,
                self.errno.desc(),
                self.errno
            )?;
        }
        writeln!(f)?;
        write!(f, "{:#}", self.backtrace)?;
        Ok(())
    }
}
