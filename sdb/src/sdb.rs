#![allow(dead_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("No supported on non-linux system.");

use libsdb::handle_command;
use libsdb::process::Process;
use libsdb::{ResultLogExt, attach};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::cell::RefCell;
use std::rc::Rc;
use std::{env, process::exit};
mod libsdb;
mod test;
mod test_utils;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        eprintln!("No arguments given");
        exit(-1);
    }
    let args_slice: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let process = attach(&args_slice);
    match process {
        Ok(process) => main_loop(&process),
        err => err.log_error(),
    }
}

fn main_loop(process: &Rc<RefCell<Process>>) {
    let mut rl = DefaultEditor::new().unwrap();
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                let mut line_str: &str = "";
                if line.is_empty() {
                    let histroy = rl.history();
                    let prev = histroy.iter().next_back();
                    if let Some(res) = prev {
                        line_str = res;
                    }
                } else {
                    line_str = &line;
                    rl.add_history_entry(line.clone())
                        .expect("Fail to save history");
                }
                if !line_str.is_empty() {
                    handle_command(process, line_str).log_error();
                }
            }
            Err(ReadlineError::Interrupted) => {
                eprintln!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                eprintln!("CTRL-D");
                break;
            }
            Err(err) => {
                eprintln!("Readline Error: {err}");
                break;
            }
        }
    }
}
