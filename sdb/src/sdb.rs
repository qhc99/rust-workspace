#[cfg(not(target_os = "linux"))]
compile_error!("No supported on non-linux system.");

use libsdb::attach;
use libsdb::wait_on_signal;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::{env, process::exit};
mod libsdb;
use libsdb::handle_command;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        eprintln!("No arguments given");
        exit(-1);
    }
    let args_slice: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let pid = attach(&args_slice);
    wait_on_signal(pid);

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
                    rl.add_history_entry(line.clone()).expect("Fail to save history");
                }
                if !line_str.is_empty(){
                    handle_command(pid, line_str);
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}
