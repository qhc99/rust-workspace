use std::{fs::File, io::BufWriter, iter::Peekable};

use xml::{writer::XmlEvent, EmitterConfig, EventWriter};

use crate::{compilation_engine::CompilationEngine, tokens::Token};

pub struct XmlCompilationEngine {
    writer: EventWriter<BufWriter<File>>,
    tokens: Peekable<Box<dyn Iterator<Item = Token>>>,
    class_name: String
}

impl XmlCompilationEngine {
    fn write_identifier(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::Identifier(t) = next {
            self.writer
                .write(XmlEvent::start_element("identifier"))
                .unwrap();
            self.writer.write(XmlEvent::characters(&t)).unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn write_sym(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::Symbol(t) = next {
            self.writer
                .write(XmlEvent::start_element("symbol"))
                .unwrap();
            self.writer.write(XmlEvent::characters(&t)).unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn write_int(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::IntegerConstant(t) = next {
            self.writer
                .write(XmlEvent::start_element("integerConstant"))
                .unwrap();
            self.writer
                .write(XmlEvent::characters(&t.to_string()))
                .unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn write_keyword(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::Keyword(t) = next {
            self.writer
                .write(XmlEvent::start_element("keyword"))
                .unwrap();
            self.writer.write(XmlEvent::characters(&t)).unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn write_string(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::StringConstant(t) = next {
            self.writer
                .write(XmlEvent::start_element("stringConstant"))
                .unwrap();
            self.writer
                .write(XmlEvent::characters(&t.to_string()))
                .unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn is_keyword(&mut self, s: &str) {
        let next = self.tokens.next().unwrap();
        if !matches!(next, Token::Keyword(t) if t == s) {
            panic!("syntax error");
        }
    }

    fn in_keywords(&mut self, s: Vec<&str>) {
        let next = self.tokens.next().unwrap();
        if !matches!(next, Token::Keyword(t) if s.contains(&t.as_str())) {
            panic!("syntax error");
        }
    }

    fn is_symbol(&mut self, s: &str) {
        let next = self.tokens.next().unwrap();
        if !matches!(next, Token::Symbol(t) if t == s) {
            panic!("syntax error");
        }
    }

    // TODO is type
}

impl CompilationEngine for XmlCompilationEngine {
    fn start(out_path: &str, tokens: Vec<Token>) {
        let file = File::create(out_path).unwrap();
        let file = BufWriter::new(file);

        let writer = EmitterConfig::new()
            .perform_indent(true)
            .create_writer(file);
        let t: Box<dyn Iterator<Item = Token>> = Box::new(tokens.into_iter());
        let mut e = XmlCompilationEngine {
            writer,
            tokens: t.peekable(),
            class_name: "".to_string()
        };
        e.compile_class();
    }

    fn compile_class(&mut self) {
        self.is_keyword("class");
        self.writer.write(XmlEvent::start_element("class")).unwrap();
        if let Some(Token::Identifier(class_name)) = self.tokens.peek(){
            self.class_name = class_name.to_owned();
        }
        else {
            panic!()
        }
        self.write_identifier();
        self.is_symbol("{");
        while matches!(self.tokens.peek(), Some(Token::Keyword(_))) {
            match self.tokens.peek() {
                Some(Token::Keyword(s)) if s == "static" || s == "field" => {
                    self.compile_class_var_dec();
                }
                _ => {
                    break;
                }
            }
        }
        while matches!(self.tokens.peek(), Some(Token::Keyword(_))) {
            match self.tokens.peek() {
                Some(Token::Keyword(s))
                    if s == "constructor" || s == "function" || s == "method" =>
                {
                    self.compile_sub_routine_dec();
                }
                _ => {
                    break;
                }
            }
        }
        self.is_symbol("}");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_class_var_dec(&mut self) {
        self.in_keywords(vec!["static", "field"]);
    }

    fn compile_sub_routine_dec(&mut self) {
        todo!()
    }

    fn compile_parameter_list(&mut self) {
        todo!()
    }

    fn compile_sub_routine_body(&mut self) {
        todo!()
    }

    fn compile_var_dec(&mut self) {
        todo!()
    }

    fn compile_var_statements(&mut self) {
        todo!()
    }

    fn compile_let(&mut self) {
        todo!()
    }

    fn compile_if(&mut self) {
        todo!()
    }

    fn compile_while(&mut self) {
        todo!()
    }

    fn compile_do(&mut self) {
        todo!()
    }

    fn compile_return(&mut self) {
        todo!()
    }

    fn compile_expression(&mut self) {
        todo!()
    }

    fn compile_term(&mut self) {
        todo!()
    }

    fn compile_expression_list(&mut self) {
        todo!()
    }
}
