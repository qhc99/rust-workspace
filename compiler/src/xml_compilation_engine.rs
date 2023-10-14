use std::{fs::File, io::BufWriter, iter::Peekable};

use xml::{writer::XmlEvent, EmitterConfig, EventWriter};

use crate::{compilation_engine::CompilationEngine, tokens::Token};

pub struct XmlCompilationEngine {
    writer: EventWriter<BufWriter<File>>,
    tokens: Peekable<Box<dyn Iterator<Item = Token>>>,
}
fn escape_str(s: String) -> String {
    let t = s.as_bytes();
    let mut v = Vec::<u8>::with_capacity(t.len());
    for i in t {
        match *i {
            b'&' => {
                v.extend("&amp;".to_string().as_bytes().to_vec());
            }
            b'<' => {
                v.extend("&lt;".to_string().as_bytes().to_vec());
            }
            b'>' => {
                v.extend("&gt;".to_string().as_bytes().to_vec());
            }
            b'\'' => {
                v.extend("&apos;".to_string().as_bytes().to_vec());
            }
            b'"' => {
                v.extend("&quot;".to_string().as_bytes().to_vec());
            }
            _ => {
                v.push(*i);
            }
        }
    }
    return String::from_utf8(v).unwrap();
}
impl XmlCompilationEngine {
    fn write_identifier(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::Identifier(t) = next {
            self.writer
                .write(XmlEvent::start_element("identifier"))
                .unwrap();
            self.writer
                .write(XmlEvent::characters(&escape_str(t)))
                .unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn write_symbol(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::Symbol(t) = next {
            self.writer
                .write(XmlEvent::start_element("symbol"))
                .unwrap();
            self.writer
                .write(XmlEvent::characters(&escape_str(t)))
                .unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn write_int_constant(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::IntegerConstant(t) = next {
            self.writer
                .write(XmlEvent::start_element("integerConstant"))
                .unwrap();
            self.writer
                .write(XmlEvent::characters(&escape_str(t.to_string())))
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
            self.writer
                .write(XmlEvent::characters(&escape_str(t)))
                .unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn write_keyword_assert(&mut self, s: &str) {
        self.assert_keyword(s);
        self.write_keyword();
    }

    fn write_string_constant(&mut self) {
        let next = self.tokens.next().unwrap();
        if let Token::StringConstant(t) = next {
            self.writer
                .write(XmlEvent::start_element("stringConstant"))
                .unwrap();
            self.writer
                .write(XmlEvent::characters(&escape_str(t)))
                .unwrap();
            self.writer.write(XmlEvent::end_element()).unwrap();
        } else {
            panic!("syntax error");
        }
    }

    fn write_type(&mut self) {
        let next = self.tokens.peek().unwrap();
        match next {
            Token::Keyword(t) if t == "int" || t == "boolean" || t == "char" => {
                self.write_keyword();
            }
            Token::Identifier(_) => {
                self.write_identifier();
            }
            _ => {
                panic!("type error")
            }
        }
    }

    fn write_symbol_assert(&mut self, s: &str) {
        self.assert_symbol(s);
        self.write_symbol();
    }

    fn assert_keyword(&mut self, s: &str) {
        let next = self.tokens.peek().unwrap();

        if !matches!(next, Token::Keyword(t) if t == s) {
            panic!("syntax error");
        }
    }

    fn assert_in_keywords(&mut self, s: Vec<&str>) {
        let next = self.tokens.peek().unwrap();
        if !matches!(next, Token::Keyword(t) if s.contains(&t.as_str())) {
            panic!("syntax error");
        }
    }

    fn assert_symbol(&mut self, s: &str) {
        let next = self.tokens.peek().unwrap();
        if !matches!(next, Token::Symbol(t) if t == s) {
            panic!("syntax error");
        }
    }

    fn next_is_op(&mut self) -> bool {
        let next = self.tokens.peek().unwrap();
        if matches!(next, Token::Symbol(t) if t == "+" || t == "-"|| t == "*" || t == "/"|| t == "&"
            || t == "|"|| t == "<"|| t == ">"|| t == "=")
        {
            return true;
        }
        return false;
    }
}

impl CompilationEngine for XmlCompilationEngine {
    fn output_extension() -> String {
        return "xml".to_string();
    }

    fn compile(out_path: &str, tokens: Vec<Token>) {
        let file = File::create(out_path).unwrap();
        let file = BufWriter::new(file);
        let mut config = EmitterConfig::new()
            .perform_indent(true)
            .write_document_declaration(false)
            .normalize_empty_elements(false);
        config.perform_escaping = false;
        let writer = config.create_writer(file);
        let t: Box<dyn Iterator<Item = Token>> = Box::new(tokens.into_iter());
        let mut e = XmlCompilationEngine {
            writer,
            tokens: t.peekable(),
        };
        e.compile_class();
    }

    fn compile_class(&mut self) {
        self.writer.write(XmlEvent::start_element("class")).unwrap();
        self.write_keyword_assert("class");
        self.write_identifier();
        self.write_symbol_assert("{");
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
        self.write_symbol_assert("}");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_class_var_dec(&mut self) {
        self.writer
            .write(XmlEvent::start_element("classVarDec"))
            .unwrap();
        self.assert_in_keywords(vec!["static", "field"]);
        self.write_keyword();
        self.write_type();
        self.write_identifier();
        while matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ",") {
            self.write_symbol_assert(",");
            self.write_identifier();
        }
        self.write_symbol_assert(";");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_sub_routine_dec(&mut self) {
        self.writer
            .write(XmlEvent::start_element("subroutineDec"))
            .unwrap();
        self.write_keyword();
        if matches!(self.tokens.peek(), Some(Token::Keyword(t)) if t == "void") {
            self.write_keyword();
        } else {
            self.write_type();
        }
        self.write_identifier();
        self.write_symbol_assert("(");
        self.compile_parameter_list();
        self.write_symbol_assert(")");
        self.compile_sub_routine_body();
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_parameter_list(&mut self) {
        self.writer
            .write(XmlEvent::start_element("parameterList"))
            .unwrap();
        if !matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ")") {
            self.write_type();
            self.write_identifier();
            while matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ",") {
                self.write_symbol_assert(",");
                self.write_type();
                self.write_identifier();
            }
        }
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_sub_routine_body(&mut self) {
        self.writer
            .write(XmlEvent::start_element("subroutineBody"))
            .unwrap();
        self.write_symbol_assert("{");
        while matches!(self.tokens.peek(), Some(Token::Keyword(t)) if t == "var") {
            self.compile_var_dec();
        }
        self.compile_statements();
        self.write_symbol_assert("}");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_var_dec(&mut self) {
        self.writer
            .write(XmlEvent::start_element("varDec"))
            .unwrap();
        self.write_keyword();
        self.write_type();
        self.write_identifier();
        while matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ",") {
            self.write_symbol_assert(",");
            self.write_identifier();
        }
        self.write_symbol_assert(";");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_statements(&mut self) {
        self.writer
            .write(XmlEvent::start_element("statements"))
            .unwrap();
        loop {
            match self.tokens.peek() {
                Some(Token::Keyword(t)) if t == "let" => {
                    self.compile_let();
                }
                Some(Token::Keyword(t)) if t == "if" => {
                    self.compile_if();
                }
                Some(Token::Keyword(t)) if t == "while" => {
                    self.compile_while();
                }
                Some(Token::Keyword(t)) if t == "do" => {
                    self.compile_do();
                }
                Some(Token::Keyword(t)) if t == "return" => {
                    self.compile_return();
                }
                _ => {
                    break;
                }
            }
        }
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_let(&mut self) {
        self.writer
            .write(XmlEvent::start_element("letStatement"))
            .unwrap();
        self.write_keyword_assert("let");
        self.write_identifier();
        if matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == "[") {
            self.write_symbol_assert("[");
            self.compile_expression();
            self.write_symbol_assert("]");
        }
        self.write_symbol_assert("=");
        self.compile_expression();
        self.write_symbol_assert(";");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_if(&mut self) {
        self.writer
            .write(XmlEvent::start_element("ifStatement"))
            .unwrap();
        self.write_keyword_assert("if");
        self.write_symbol_assert("(");
        self.compile_expression();
        self.write_symbol_assert(")");
        self.write_symbol_assert("{");
        self.compile_statements();
        self.write_symbol_assert("}");
        if matches!(self.tokens.peek(), Some(Token::Keyword(t)) if t == "else") {
            self.write_keyword();
            self.write_symbol_assert("{");
            self.compile_statements();
            self.write_symbol_assert("}");
        }
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_while(&mut self) {
        self.writer
            .write(XmlEvent::start_element("whileStatement"))
            .unwrap();
        self.write_keyword_assert("while");
        self.write_symbol_assert("(");
        self.compile_expression();
        self.write_symbol_assert(")");
        self.write_symbol_assert("{");
        self.compile_statements();
        self.write_symbol_assert("}");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_do(&mut self) {
        self.writer
            .write(XmlEvent::start_element("doStatement"))
            .unwrap();
        self.write_keyword_assert("do");
        // subroutine call
        let next = self.tokens.next().unwrap();
        let write_pulled_identifier = || {
            if let Token::Identifier(t) = next {
                self.writer
                    .write(XmlEvent::start_element("identifier"))
                    .unwrap();
                self.writer.write(XmlEvent::characters(&t)).unwrap();
                self.writer.write(XmlEvent::end_element()).unwrap();
            }
        };
        match self.tokens.peek() {
            Some(Token::Symbol(t)) if t == "(" => {
                write_pulled_identifier();
                self.write_symbol_assert("(");
                self.compile_expression_list();
                self.write_symbol_assert(")");
            }
            Some(Token::Symbol(t)) if t == "." => {
                write_pulled_identifier();
                self.write_symbol_assert(".");
                self.write_identifier();
                self.write_symbol_assert("(");
                self.compile_expression_list();
                self.write_symbol_assert(")");
            }
            _ => {
                panic!()
            }
        }
        self.write_symbol_assert(";");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_return(&mut self) {
        self.writer
            .write(XmlEvent::start_element("returnStatement"))
            .unwrap();
        self.write_keyword_assert("return");
        if !matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ";") {
            self.compile_expression();
        }
        self.write_symbol_assert(";");
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_expression(&mut self) {
        self.writer
            .write(XmlEvent::start_element("expression"))
            .unwrap();
        self.compile_term();
        while self.next_is_op() {
            self.write_symbol();
            self.compile_term();
        }
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_term(&mut self) {
        self.writer.write(XmlEvent::start_element("term")).unwrap();
        match self.tokens.peek() {
            Some(Token::IntegerConstant(_)) => {
                self.write_int_constant();
            }
            Some(Token::StringConstant(_)) => {
                self.write_string_constant();
            }
            Some(Token::Keyword(t))
                if t == "true" || t == "false" || t == "this" || t == "null" =>
            {
                self.write_keyword();
            }
            Some(Token::Symbol(t)) if t == "(" => {
                self.write_symbol();
                self.compile_expression();
                self.write_symbol_assert(")");
            }
            Some(Token::Symbol(t)) if t == "-" || t == "~" => {
                self.write_symbol();
                self.compile_term();
            }
            Some(Token::Identifier(_)) => {
                let next = self.tokens.next().unwrap();
                let write_pulled_identifier = || {
                    if let Token::Identifier(t) = next {
                        self.writer
                            .write(XmlEvent::start_element("identifier"))
                            .unwrap();
                        self.writer.write(XmlEvent::characters(&t)).unwrap();
                        self.writer.write(XmlEvent::end_element()).unwrap();
                    }
                };
                match self.tokens.peek() {
                    Some(Token::Symbol(t)) if t == "[" => {
                        write_pulled_identifier();
                        self.write_symbol_assert("[");
                        self.compile_expression();
                        self.write_symbol_assert("]");
                    }
                    Some(Token::Symbol(t)) if t == "(" => {
                        write_pulled_identifier();
                        self.write_symbol_assert("(");
                        self.compile_expression_list();
                        self.write_symbol_assert(")");
                    }
                    Some(Token::Symbol(t)) if t == "." => {
                        write_pulled_identifier();
                        self.write_symbol_assert(".");
                        self.write_identifier();
                        self.write_symbol_assert("(");
                        self.compile_expression_list();
                        self.write_symbol_assert(")");
                    }
                    _ => {
                        write_pulled_identifier();
                    }
                }
            }
            _ => {
                panic!()
            }
        }
        self.writer.write(XmlEvent::end_element()).unwrap();
    }

    fn compile_expression_list(&mut self) -> u32 {
        self.writer
            .write(XmlEvent::start_element("expressionList"))
            .unwrap();
        if !matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ")") {
            self.compile_expression();
            while matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ",") {
                self.write_symbol();
                self.compile_expression();
            }
        }
        self.writer.write(XmlEvent::end_element()).unwrap();
        return 0;
    }
}
