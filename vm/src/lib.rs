mod code_writer;
mod command_type;
mod parser;
mod program;

#[no_mangle]
pub extern "C" fn compile_single_file() {
    program::compile_single_file();
}
