use std::iter::Peekable;

use crate::{
    code_generator::{CodeGenerator, Command, Segment},
    compilation_engine::CompilationEngine,
    sym_table::{SymbolTable, VarType},
    tokens::Token,
};

pub struct VmCompilationEngine {
    code_gen: CodeGenerator,
    tokens: Peekable<Box<dyn Iterator<Item = Token>>>,
    class_name: String,
    func_name: String,
    func_type: String,
    sym_table: SymbolTable,
    if_count: u32,
    while_count: u32,
}
impl VmCompilationEngine {
    fn pop_keyword_assert(&mut self, arg: &str) {
        let next = self.tokens.next().unwrap();
        match next {
            Token::Keyword(t) if t == arg => {}
            _ => {
                panic!()
            }
        }
    }

    fn pop_identifier(&mut self) -> String {
        let next = self.tokens.next().unwrap();
        match next {
            Token::Identifier(t) => t,
            _ => {
                panic!()
            }
        }
    }

    fn pop_symbol_assert(&mut self, arg: &str) {
        let next = self.tokens.next().unwrap();
        match next {
            Token::Symbol(t) if t == arg => {}
            _ => {
                panic!()
            }
        }
    }

    fn assert_in_keywords(&mut self, s: Vec<&str>) {
        let next = self.tokens.peek().unwrap();
        if !matches!(next, Token::Keyword(t) if s.contains(&t.as_str())) {
            panic!("syntax error");
        }
    }

    fn pop_keyword(&mut self) -> String {
        let next = self.tokens.next().unwrap();
        match next {
            Token::Keyword(t) => t,
            _ => {
                panic!()
            }
        }
    }

    fn pop_type(&mut self) -> String {
        let next = self.tokens.next().unwrap();
        match next {
            Token::Keyword(t) if t == "int" || t == "boolean" || t == "char" => t,
            Token::Identifier(t) => t,
            _ => {
                panic!("type error")
            }
        }
    }

    fn pop_symbol(&mut self) -> String {
        let next = self.tokens.next().unwrap();
        match next {
            Token::Symbol(t) => t,
            _ => {
                panic!()
            }
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

    fn pop_string_constant(&mut self) -> String {
        let next = self.tokens.next().unwrap();
        if let Token::StringConstant(t) = next {
            t
        } else {
            panic!("syntax error");
        }
    }

    fn pop_int_constant(&mut self) -> u32 {
        let next = self.tokens.next().unwrap();
        if let Token::IntegerConstant(t) = next {
            t
        } else {
            panic!("syntax error");
        }
    }
}

impl CompilationEngine for VmCompilationEngine {
    fn compile(out_path: &str, tokens: Vec<Token>) {
        let t: Box<dyn Iterator<Item = Token>> = Box::new(tokens.into_iter());
        let mut e = VmCompilationEngine {
            code_gen: CodeGenerator::new(out_path),
            tokens: t.peekable(),
            class_name: "".to_string(),
            func_name: "".to_string(),
            func_type: "".to_string(),
            sym_table: SymbolTable::new(),
            if_count: 0,
            while_count: 0,
        };
        e.compile_class();
    }

    fn compile_class(&mut self) {
        self.pop_keyword_assert("class");
        self.class_name = self.pop_identifier();
        self.pop_symbol_assert("{");
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
        self.pop_symbol_assert("}");
    }

    fn compile_class_var_dec(&mut self) {
        self.assert_in_keywords(vec!["static", "field"]);
        let k = self.pop_keyword();
        let tp = self.pop_type();
        let name = self.pop_identifier();
        let kind = if k == "static" {
            VarType::Static
        } else {
            VarType::Field
        };
        self.sym_table.define(&name, &tp, &kind);
        while matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ",") {
            self.pop_symbol_assert(",");
            let name = self.pop_identifier();
            self.sym_table.define(&name, &tp, &kind);
        }
        self.pop_symbol_assert(";");
    }

    fn compile_sub_routine_dec(&mut self) {
        self.sym_table.start_subroutine();
        self.func_type = self.pop_keyword();
        if matches!(self.tokens.peek(), Some(Token::Keyword(t)) if t == "void") {
            self.pop_keyword();
        } else {
            self.pop_type();
        };
        self.func_name = self.pop_identifier();
        self.pop_symbol_assert("(");
        self.compile_parameter_list();
        self.pop_symbol_assert(")");
        self.compile_sub_routine_body();
    }

    fn compile_parameter_list(&mut self) {
        if !matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ")") {
            let tp = self.pop_type();
            let name = self.pop_identifier();
            self.sym_table.define(&name, &tp, &VarType::Arg);
            while matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ",") {
                self.pop_symbol_assert(",");
                let tp = self.pop_type();
                let name = self.pop_identifier();
                self.sym_table.define(&name, &tp, &VarType::Arg);
            }
        }
    }

    fn compile_sub_routine_body(&mut self) {
        self.pop_symbol_assert("{");
        while matches!(self.tokens.peek(), Some(Token::Keyword(t)) if t == "var") {
            self.compile_var_dec();
        }
        let var_count = self.sym_table.var_count(&VarType::Var);
        self.code_gen.write_function(
            &format!("{}.{}", self.class_name, self.func_name),
            var_count,
        );
        if self.func_type == "constructor" {
            self.code_gen.write_push(&Segment::Const, var_count);
            self.code_gen.write_call(&"Memory.alloc", 1);
            self.code_gen.write_pop(&Segment::Pointer, 0);
        }
        self.compile_statements();
        self.pop_symbol_assert("}");
    }

    fn compile_var_dec(&mut self) {
        self.pop_keyword();
        let tp = self.pop_type();
        let name = self.pop_identifier();
        self.sym_table.define(&name, &tp, &VarType::Var);
        while matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ",") {
            self.pop_symbol_assert(",");
            let name = self.pop_identifier();
            self.sym_table.define(&name, &tp, &VarType::Var);
        }
        self.pop_symbol_assert(";");
    }

    fn compile_statements(&mut self) {
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
    }

    fn compile_let(&mut self) {
        self.pop_keyword_assert("let");
        let name = self.pop_identifier();
        let kind = self.sym_table.kind_of(&name);
        let idx = self.sym_table.index_of(&name);
        let seg = kind.into();
        if matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == "[") {
            self.code_gen.write_push(&seg, idx);
            self.pop_symbol_assert("[");
            self.compile_expression();
            self.pop_symbol_assert("]");

            self.code_gen.write_arithmetic(&Command::Add);

            self.pop_symbol_assert("=");
            self.compile_expression();
            self.pop_symbol_assert(";");

            self.code_gen.write_pop(&Segment::Temp, 0);
            self.code_gen.write_pop(&Segment::Pointer, 1);
            self.code_gen.write_push(&Segment::Temp, 0);
            self.code_gen.write_pop(&Segment::That, 0);
        } else {
            self.pop_symbol_assert("=");
            self.compile_expression();
            self.pop_symbol_assert(";");
            self.code_gen.write_pop(&seg, idx);
        }
    }

    fn compile_if(&mut self) {
        self.pop_keyword_assert("if");

        self.pop_symbol_assert("(");
        self.compile_expression();
        self.pop_symbol_assert(")");
        self.code_gen.write_arithmetic(&Command::Not);
        self.code_gen
            .write_if(&format!("{}.IF_FALSE${}", self.class_name, self.if_count));

        self.pop_symbol_assert("{");
        self.compile_statements();
        self.pop_symbol_assert("}");

        self.code_gen
            .write_goto(&format!("{}.IF_END${}", self.class_name, self.if_count));
        self.code_gen
            .write_label(&format!("{}.IF_FALSE${}", self.class_name, self.if_count));
        if matches!(self.tokens.peek(), Some(Token::Keyword(t)) if t == "else") {
            self.pop_keyword();
            self.pop_symbol_assert("{");
            self.compile_statements();
            self.pop_symbol_assert("}");
        }
        self.code_gen
            .write_label(&format!("{}.IF_END${}", self.class_name, self.if_count));
        self.if_count += 1;
    }

    fn compile_while(&mut self) {
        self.pop_keyword_assert("while");

        self.code_gen.write_label(&format!(
            "{}.WHILE_START${}",
            self.class_name, self.while_count
        ));
        self.pop_symbol_assert("(");
        self.compile_expression();
        self.pop_symbol_assert(")");

        self.code_gen.write_arithmetic(&Command::Not);
        self.code_gen.write_if(&format!(
            "{}.WHILE_END${}",
            self.class_name, self.while_count
        ));

        self.pop_symbol_assert("{");
        self.compile_statements();
        self.pop_symbol_assert("}");
        self.code_gen.write_goto(&format!(
            "{}.WHILE_START${}",
            self.class_name, self.while_count
        ));

        self.code_gen.write_label(&format!(
            "{}.WHILE_END${}",
            self.class_name, self.while_count
        ));
        self.while_count += 1;
    }

    fn compile_do(&mut self) {
        self.pop_keyword_assert("do");
        // subroutine call
        let next = self.tokens.next().unwrap();
        let pulled_identifier = if let Token::Identifier(t) = next {
            t
        } else {
            panic!()
        };

        match self.tokens.peek() {
            Some(Token::Symbol(t)) if t == "(" => {
                let func_name = pulled_identifier;
                self.pop_symbol_assert("(");
                let n_args = self.compile_expression_list();
                self.pop_symbol_assert(")");
                self.code_gen.write_call(&func_name, n_args);
            }
            Some(Token::Symbol(t)) if t == "." => {
                let obj_or_class_name = pulled_identifier;
                if self.sym_table.has_id(&obj_or_class_name) {
                    let idx = self.sym_table.index_of(&obj_or_class_name);
                    let kind = self.sym_table.kind_of(&obj_or_class_name);
                    let seg = kind.into();
                    self.code_gen.write_push(&seg, idx);
                }
                self.pop_symbol_assert(".");
                let method_name = self.pop_identifier();
                self.pop_symbol_assert("(");
                let n_args = self.compile_expression_list();
                self.pop_symbol_assert(")");
                if self.sym_table.has_id(&obj_or_class_name) {
                    self.code_gen.write_call(
                        &format!(
                            "{}.{}",
                            self.sym_table.type_of(&obj_or_class_name),
                            method_name
                        ),
                        n_args + 1,
                    );
                } else {
                    self.code_gen
                        .write_call(&format!("{}.{}", obj_or_class_name, method_name), n_args);
                }
            }
            _ => {
                panic!()
            }
        }
        self.pop_symbol_assert(";");
        self.code_gen.write_pop(&Segment::Temp, 0);
    }

    fn compile_return(&mut self) {
        self.pop_keyword_assert("return");
        if !matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ";") {
            self.compile_expression();
        }
        self.pop_symbol_assert(";");
        self.code_gen.write_return();
    }

    fn compile_expression(&mut self) {
        self.compile_term();
        while self.next_is_op() {
            let op = self.pop_symbol();
            self.compile_term();
            match op.as_str() {
                "+" => self.code_gen.write_arithmetic(&Command::Add),
                "-" => self.code_gen.write_arithmetic(&Command::Sub),
                "*" => self.code_gen.write_call("Math.multiply", 2),
                "/" => self.code_gen.write_call("Math.divide", 2),
                "&" => self.code_gen.write_arithmetic(&Command::And),
                "|" => self.code_gen.write_arithmetic(&Command::Or),
                "<" => self.code_gen.write_arithmetic(&Command::Lt),
                ">" => self.code_gen.write_arithmetic(&Command::Gt),
                "=" => self.code_gen.write_arithmetic(&Command::Eq),
                _ => {
                    panic!()
                }
            }
        }
    }

    fn compile_term(&mut self) {
        match self.tokens.peek() {
            Some(Token::IntegerConstant(_)) => {
                let i = self.pop_int_constant();
                self.code_gen.write_push(&Segment::Const, i);
            }
            Some(Token::StringConstant(_)) => {
                let s = self.pop_string_constant();
                let len = s.len();
                self.code_gen.write_push(&Segment::Const, len as u32);
                self.code_gen.write_call("String.new", 1);
                for i in s.as_bytes() {
                    self.code_gen.write_push(&Segment::Const, *i as u32);
                    self.code_gen.write_call("String.appendChar", 1);
                }
            }
            Some(Token::Keyword(t))
                if t == "true" || t == "false" || t == "this" || t == "null" =>
            {
                let k = self.pop_keyword();
                match k.as_str() {
                    "true" => {
                        self.code_gen.write_push(&Segment::Const, 0);
                        self.code_gen.write_arithmetic(&Command::Not)
                    }
                    "false" => self.code_gen.write_push(&Segment::Const, 0),
                    "this" => self.code_gen.write_push(&Segment::Pointer, 0),
                    "null" => self.code_gen.write_push(&Segment::Const, 0),
                    _ => {
                        panic!()
                    }
                }
            }
            Some(Token::Symbol(t)) if t == "(" => {
                self.pop_symbol();
                self.compile_expression();
                self.pop_symbol_assert(")");
            }
            Some(Token::Symbol(t)) if t == "-" || t == "~" => {
                let s = self.pop_symbol();
                self.compile_term();
                match s.as_str() {
                    "-" => self.code_gen.write_arithmetic(&Command::Neg),
                    "~" => self.code_gen.write_arithmetic(&Command::Not),
                    _ => {
                        panic!()
                    }
                }
            }
            Some(Token::Identifier(_)) => {
                let next = self.tokens.next().unwrap();
                let get_pulled_identifier = || {
                    if let Token::Identifier(t) = next {
                        return t;
                    } else {
                        panic!()
                    }
                };
                match self.tokens.peek() {
                    Some(Token::Symbol(t)) if t == "[" => {
                        let arr_name = get_pulled_identifier();
                        let idx = self.sym_table.index_of(&arr_name);
                        let kind = self.sym_table.kind_of(&arr_name);
                        let seg = kind.into();
                        self.code_gen.write_push(&seg, idx);
                        self.pop_symbol_assert("[");
                        self.compile_expression();
                        self.pop_symbol_assert("]");
                        self.code_gen.write_arithmetic(&Command::Add);

                        self.code_gen.write_pop(&Segment::Pointer, 1);
                        self.code_gen.write_push(&Segment::That, 0);
                    }
                    Some(Token::Symbol(t)) if t == "(" => {
                        let func_name = get_pulled_identifier();
                        self.pop_symbol_assert("(");
                        let n_args = self.compile_expression_list();
                        self.pop_symbol_assert(")");
                        self.code_gen.write_call(&func_name, n_args);
                    }
                    Some(Token::Symbol(t)) if t == "." => {
                        let obj_or_class_name = get_pulled_identifier();
                        if self.sym_table.has_id(&obj_or_class_name) {
                            let kind = self.sym_table.kind_of(&obj_or_class_name);
                            let seg = kind.into();
                            self.code_gen
                                .write_push(&seg, self.sym_table.index_of(&obj_or_class_name));
                        }
                        self.pop_symbol_assert(".");
                        let method_name = self.pop_identifier();
                        self.pop_symbol_assert("(");
                        let n_args = self.compile_expression_list();
                        self.pop_symbol_assert(")");
                        if self.sym_table.has_id(&obj_or_class_name) {
                            self.code_gen.write_call(
                                &format!(
                                    "{}.{}",
                                    self.sym_table.type_of(&obj_or_class_name),
                                    method_name
                                ),
                                n_args + 1,
                            );
                        } else {
                            self.code_gen.write_call(
                                &format!("{}.{}", obj_or_class_name, method_name),
                                n_args,
                            );
                        }
                    }
                    _ => {
                        get_pulled_identifier();
                    }
                }
            }
            _ => {
                panic!()
            }
        }
    }

    fn compile_expression_list(&mut self) -> u32 {
        let mut count = 0;
        if !matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ")") {
            self.compile_expression();
            count += 1;
            while matches!(self.tokens.peek(), Some(Token::Symbol(t)) if t == ",") {
                self.pop_symbol();
                self.compile_expression();
                count += 1;
            }
        }
        return count;
    }
}
