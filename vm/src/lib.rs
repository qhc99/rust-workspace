
mod program;
mod code_writer;
mod parser;
mod command_type;

#[no_mangle]
pub extern "C" fn compile_single_file(){
    program::compile_single_file();
}