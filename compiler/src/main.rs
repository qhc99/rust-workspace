#![allow(dead_code)]
#![allow(clippy::needless_return)]
#[macro_use]
extern crate derive_more;

mod compilation_engine;
mod sym_table;
mod tests;
mod tokenizer;
mod tokens;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use compilation_engine::CompilationEngine;
use tokenizer::Tokenizer;
use vm_compilation_engine::VmCompilationEngine;
mod code_generator;
mod vm_compilation_engine;
mod xml_compilation_engine;

fn main() {
    compile::<VmCompilationEngine>();
}

pub fn compile<Engine>()
where
    Engine: CompilationEngine,
{
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Arg num should be 1");
    }
    let input_path: &str = &args[1];
    let input_path = Path::new(input_path);
    if !input_path.exists() {
        panic!("input path not exists")
    }
    let tn = Tokenizer::new();
    if input_path.is_file() {
        let out_path = PathBuf::from(input_path);
        out_path.with_extension(Engine::output_extension());
        let v = tn.tokenize(Path::new(input_path));
        Engine::compile(out_path.to_str().unwrap(), v);
    } else if input_path.is_dir() {
        let entries = fs::read_dir(input_path).unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() && path.extension() == Some(std::ffi::OsStr::new("jack")) {
                let v = tn.tokenize(&path);
                let out_path = path.with_extension(Engine::output_extension());
                Engine::compile(out_path.to_str().unwrap(), v);
            }
        }
    } else {
        panic!("neither dir nor file")
    }
}
