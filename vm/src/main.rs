#![allow(clippy::needless_return)]
use std::{io, env};

use parser::Parser;
mod code_writer;
mod command_type;
mod parser;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Arg count is not 2");
    }
    let input_path: &str = &args[1];

    // strip comment and all splaces
    // for line in lines.into_iter().flatten() {
    //     let s = strip_comment(line.as_str()).trim();
    //     if !s.is_empty() {
    //         clean_lines.push(s);
    //     }
    // }
    return Ok(());
}
