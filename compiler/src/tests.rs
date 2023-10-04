use std::{fs::File, io::BufWriter, path::Path};

use xml::{EmitterConfig, writer::XmlEvent};

use crate::{tokenizer::Tokenizer, tokens::Token, xml_compilation_engine::XmlCompilationEngine, compilation_engine::CompilationEngine};

pub fn test_tokenizer_xml() {
    let out_path = "MainT.xml";
    let input_path = "C:/Users/Nathan/VSCodeProjects/nand2tetris/projects/10/Square/Main.jack";
    print_token_xml(out_path, input_path);

    let out_path = "SquareT.xml";
    let input_path = "C:/Users/Nathan/VSCodeProjects/nand2tetris/projects/10/Square/Square.jack";
    print_token_xml(out_path, input_path);

    let out_path = "SquareGameT.xml";
    let input_path =
        "C:/Users/Nathan/VSCodeProjects/nand2tetris/projects/10/Square/SquareGame.jack";
    print_token_xml(out_path, input_path);
}

pub fn test_parser_xml() {
    let out_path = "Main.xml";
    let input_path = "C:/Users/Nathan/VSCodeProjects/nand2tetris/projects/10/Square/Main.jack";
    let tn = Tokenizer::new();
    let v = tn.tokenize(Path::new(input_path));
    XmlCompilationEngine::start(out_path, v);

    let out_path = "Square.xml";
    let input_path = "C:/Users/Nathan/VSCodeProjects/nand2tetris/projects/10/Square/Square.jack";
    let tn = Tokenizer::new();
    let v = tn.tokenize(Path::new(input_path));
    XmlCompilationEngine::start(out_path, v);

    let out_path = "SquareGame.xml";
    let input_path =
        "C:/Users/Nathan/VSCodeProjects/nand2tetris/projects/10/Square/SquareGame.jack";
    let tn = Tokenizer::new();
    let v = tn.tokenize(Path::new(input_path));
    XmlCompilationEngine::start(out_path, v);
}


fn print_token_xml(out_path: &str, input_path: &str) {
    let file = File::create(out_path).unwrap();
    let file = BufWriter::new(file);

    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(file);

    let tn = Tokenizer::new();
    let v = tn.tokenize(Path::new(input_path));
    writer.write(XmlEvent::start_element("tokens")).unwrap();
    for i in v {
        match i {
            Token::Keyword(k) => {
                writer.write(XmlEvent::start_element("keyword")).unwrap();
                writer.write(XmlEvent::characters(&k)).unwrap();
                writer.write(XmlEvent::end_element()).unwrap();
            }
            Token::Symbol(s) => {
                writer.write(XmlEvent::start_element("symbol")).unwrap();
                writer.write(XmlEvent::characters(&s)).unwrap();
                writer.write(XmlEvent::end_element()).unwrap();
            }
            Token::IntegerConstant(i) => {
                writer
                    .write(XmlEvent::start_element("integerConstant"))
                    .unwrap();
                writer.write(XmlEvent::characters(&i.to_string())).unwrap();
                writer.write(XmlEvent::end_element()).unwrap();
            }
            Token::StringConstant(s) => {
                writer
                    .write(XmlEvent::start_element("stringConstant"))
                    .unwrap();
                writer.write(XmlEvent::characters(&s)).unwrap();
                writer.write(XmlEvent::end_element()).unwrap();
            }
            Token::Identifier(i) => {
                writer.write(XmlEvent::start_element("identifier")).unwrap();
                writer.write(XmlEvent::characters(&i)).unwrap();
                writer.write(XmlEvent::end_element()).unwrap();
            }
            _ => {
                panic!("unexpected token")
            }
        }
    }
    writer.write(XmlEvent::end_element()).unwrap();
}
