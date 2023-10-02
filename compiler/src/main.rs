mod compilation_engine;
mod tokenizer;
mod tokens;
mod tests;
use tests::test_token_xml;
mod vm_compilation_engine;
mod xml_compilation_engine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    test_token_xml();
    Ok(())
}


