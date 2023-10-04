mod compilation_engine;
mod tokenizer;
mod tokens;
mod tests;
use tests::{test_tokenizer_xml, test_parser_xml};
mod vm_compilation_engine;
mod xml_compilation_engine;

fn main()  {
    test_parser_xml();
}


