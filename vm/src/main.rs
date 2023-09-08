#![allow(clippy::needless_return)]

use program::compile_single_file;

mod code_writer;
mod parser;
mod command_type;
mod program;

fn main() {
    compile_single_file();
}



