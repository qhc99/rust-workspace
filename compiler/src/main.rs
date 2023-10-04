mod compilation_engine;
mod tests;
mod tokenizer;
mod tokens;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use compilation_engine::CompilationEngine;
use tests::{test_parser_xml, test_tokenizer_xml};
use tokenizer::Tokenizer;
use xml_compilation_engine::XmlCompilationEngine;
mod vm_compilation_engine;
mod xml_compilation_engine;

fn main() {
    compile_to_xml();
}

pub fn compile_to_xml() {
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
        out_path.with_extension("xml");
        let v = tn.tokenize(Path::new(input_path));
        XmlCompilationEngine::start(out_path.to_str().unwrap(), v);
    } else if input_path.is_dir() {
        if let Ok(entries) = fs::read_dir(input_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() && path.extension() == Some(std::ffi::OsStr::new("jack")) {
                        let v = tn.tokenize(&path);
                        let out_path = path.with_extension("xml");
                        XmlCompilationEngine::start(out_path.to_str().unwrap(), v);
                    }
                }
            }
        }
    } else {
        panic!("neither dir nor file")
    }
}
