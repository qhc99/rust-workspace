#![allow(clippy::needless_return)]

use program::compile_single_file;

mod code_writer;
mod command_type;
mod parser;
mod program;

fn main() {
    compile_single_file();
}
