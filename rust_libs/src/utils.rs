use std::io::Result;

use crate::f_loc;
pub trait MapErrMsg<E> {
    fn log_err(self, msg: &str) -> E;
}

impl<T> MapErrMsg<Result<T>> for Result<T> {
    fn log_err(self, msg: &str) -> Result<T> {
        if self.is_err() {
            eprintln!("{msg}");
        }
        self
    }
}
