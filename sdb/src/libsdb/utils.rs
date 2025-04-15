use nix::Result;

pub trait ResultLogExt<T> {
    fn log_error(self);
}

impl<T> ResultLogExt<T> for Result<T> {
    fn log_error(self) {
        self.inspect_err(|e| log::error!("{e}")).ok();
    }
}
