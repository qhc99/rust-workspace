use super::sdb_error::SdbError;
use nix::Result as NixResult;

pub trait ResultLogExt<T> {
    fn log_error(self);
}

impl<T> ResultLogExt<T> for NixResult<T> {
    fn log_error(self) {
        self.inspect_err(|e| log::error!("{e}")).ok();
    }
}

impl<T> ResultLogExt<T> for Result<T, SdbError> {
    fn log_error(self) {
        self.inspect_err(|e| log::error!("{e}")).ok();
    }
}
