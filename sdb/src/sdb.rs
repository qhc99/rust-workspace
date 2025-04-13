#![cfg(target_os = "linux")]
use std::{env, process::exit};

use libsdb::attach;
use nix::sys::wait::{WaitPidFlag, waitpid};
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        eprintln!("No arguments given");
        exit(-1);
    }
    let args_slice: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let pid = attach(&args_slice);
    let options = WaitPidFlag::from_bits(0);
    if let Ok(wait_status) = waitpid(pid, options) {
    } else {
        eprintln!("waitpid failed");
    }
}
