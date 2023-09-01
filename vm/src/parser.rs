use regex::Regex;

use crate::command_type::CommandType;
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Lines},
    iter::Peekable,
    path::Path,
};

pub struct Parser {
    cmd_iter: Peekable<Box<dyn Iterator<Item = String>>>,
    cmd: Option<String>,
    arg1: Option<String>,
    arg2: Option<i32>,
    regex_whitespaces: Regex,
}

impl Parser {
    pub fn new(input_path: &str) -> Self {
        let line_reader = Self::read_lines(input_path).expect("Cannot find file");
        let iter = line_reader
            .map(|r| -> _ {
                Self::strip_comment(&(r.expect("line read error")))
                    .trim()
                    .to_string()
            })
            .filter(|s| -> _ { !s.is_empty() });
        let b: Box<dyn Iterator<Item = String>> = Box::new(iter);
        Self {
            cmd_iter: b.peekable(),
            cmd: None,
            arg1: None,
            arg2: None,
            regex_whitespaces: Regex::new(r"\s+").expect("regex compile error"),
        }
    }

    pub fn has_more_commands(&mut self) -> bool {
        return self.cmd_iter.peek().is_some();
    }

    pub fn advance(&mut self) {
        let s = self
            .cmd_iter
            .next()
            .expect("advance called when no more commands");
        let mut l = self.regex_whitespaces.split(&s);
        self.cmd = l.next().map(|a| -> _ { a.to_owned() });
        self.arg1 = l.next().map(|a| -> _ { a.to_owned() });
        self.arg2 = l
            .next()
            .map(|a| -> _ { a.parse::<i32>().expect("arg2 is not int") });
    }

    pub fn command_type(&mut self) -> CommandType {
        let c = self.arg1.take().expect("cmd is empty");
        match &c as &str {
            "add" | "sub" | "neg" | "eq" | "gt" | "lt" | "and" | "or" | "not" => {
                CommandType::Arithmeic
            }
            "push" => CommandType::Push,
            "pop" => CommandType::Pop,
            "label" => CommandType::Label,
            "goto" => CommandType::Goto,
            "if-goto" => CommandType::If,
            "function" => CommandType::Function,
            "return" => CommandType::Return,
            "call" => CommandType::Call,
            other => {
                panic!("cmd no match: {}", other)
            }
        }
    }

    pub fn arg1(&mut self) -> String {
        self.arg1.take().expect("arg1 is empty")
    }

    pub fn arg2(&mut self) -> i32 {
        self.arg2.take().expect("arg2 is empty")
    }

    fn strip_comment(s: &str) -> &str {
        let chrs = s.as_bytes();
        for (i, c) in chrs.iter().enumerate() {
            if *c == b'/' {
                return &s[..i];
            }
        }
        return s;
    }

    fn read_lines<P>(filename: P) -> io::Result<Lines<BufReader<File>>>
    where
        P: AsRef<Path>,
    {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }
}
