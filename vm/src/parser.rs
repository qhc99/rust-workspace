use regex::Regex;

use crate::command_type::CommandType;
use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    iter::Peekable,
};

pub struct Parser {
    cmd_iter: Peekable<Box<dyn Iterator<Item = io::Result<String>>>>,
    cmd: Option<String>,
    arg1: Option<String>,
    arg2: Option<i16>,
    regex_whitespaces: Regex,
}

impl Parser {
    pub fn new(input: File) -> io::Result<Self> {
        let lines = BufReader::new(input).lines();
        let iter = lines
            .map(|r| -> _ {
                r.map(|s|->_{
                    Self::strip_comment(&s)
                    .trim()
                    .to_string()
                })
            })
            .filter(|r| -> bool { r.as_ref().map_or(false, |s|->_{!s.is_empty()}) 
        });
        let b: Box<dyn Iterator<Item = io::Result<String>>> = Box::new(iter);
        Ok(Self {
            cmd_iter: b.peekable(),
            cmd: None,
            arg1: None,
            arg2: None,
            regex_whitespaces: Regex::new(r"\s+").unwrap(),
        })
    }

    pub fn has_more_commands(&mut self) -> bool {
        return self.cmd_iter.peek().is_some();
    }

    pub fn advance(&mut self)->io::Result<()> {
        let s = self
            .cmd_iter
            .next()
            .expect("advance called when no more commands");
        let s = s?;
        let mut l = self.regex_whitespaces.split(&s);
        self.cmd = l.next().map(|a| -> _ { a.to_owned() });
        self.arg1 = l.next().map(|a| -> _ { a.to_owned() });
        self.arg2 = l
            .next()
            .map(|a| -> _ { a.parse::<i16>().expect("arg2 is not int") });
        Ok(())
    }

    pub fn command_type(&mut self) -> CommandType {
        let c = self.cmd.take().expect("cmd is empty");
        match &c as &str {
            "add" | "sub" | "neg" | "eq" | "gt" | "lt" | "and" | "or" | "not" => {
                self.cmd = Some(c);
                CommandType::Arithmetic
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

    pub fn arg2(&mut self) -> i16 {
        self.arg2.take().expect("arg2 is empty")
    }

    pub fn raw_cmd(&mut self)->String{
        self.cmd.take().expect("cmd is empty")
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
}
