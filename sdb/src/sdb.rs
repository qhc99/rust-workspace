#[cfg(not(target_os = "linux"))]
compile_error!("No supported on non-linux system.");

use libsdb::process::Process;
use libsdb::{ResultLogExt, attach};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::{env, process::exit};
mod libsdb;
use libsdb::handle_command;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        log::error!("No arguments given");
        exit(-1);
    }
    let args_slice: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let process = attach(&args_slice);
    match process {
        Ok(mut process) => main_loop(&mut process),
        err => err.log_error(),
    }
}

fn main_loop(process: &mut Box<Process>) {
    let mut rl = DefaultEditor::new().unwrap();
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                let mut line_str: &str = "";
                if line == "" {
                    let histroy = rl.history();
                    let prev = histroy.iter().rev().next();
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
                log::error!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                log::error!("CTRL-D");
                break;
            }
            Err(err) => {
                log::error!("Readline Error: {:?}", err);
                break;
            }
        }
    }
}
