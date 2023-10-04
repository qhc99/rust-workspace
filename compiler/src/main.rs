mod compilation_engine;
mod tokenizer;
mod tokens;
mod tests;
use std::{env, path::{Path, PathBuf}};

use compilation_engine::CompilationEngine;
use tests::{test_tokenizer_xml, test_parser_xml};
use tokenizer::Tokenizer;
use xml_compilation_engine::XmlCompilationEngine;
mod vm_compilation_engine;
mod xml_compilation_engine;

fn main()  {
    xml_compile_single_file();
}

pub fn xml_compile_single_file(){
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Arg num should be 1");
    }
    let input_path: &str = &args[1];
    let input_path = Path::new(input_path);
    if !input_path.exists() {
        panic!("input path not exists")
    }
    let out_path = PathBuf::from(input_path);
    out_path.with_extension("xml");

    let tn = Tokenizer::new();
    let v = tn.tokenize(Path::new(input_path));
    XmlCompilationEngine::start(out_path.to_str().unwrap(), v);
}


