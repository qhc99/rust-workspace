use regex::Regex;
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::tokens::Token;

pub struct Tokenizer {
    re: Regex,
}

impl Tokenizer {
    pub fn new() -> Self {
        let keywords1 = "class|constructor|function|method|field|static|var|int";
        let keywords2 = "char|boolean|void|true|false|null|this|let|do|if|else|while|return";
        let keywords = format!("{keywords1}|{keywords2}");
        let symbols = r"\{|\}|\(|\)|\[|\]|\.|,|;|\+|-|\*|/|&|\||<|>|=|~";
        let str_pattern = "\".+?\"";
        let id_pattern = r"[_a-zA-Z]+[_\w]*";
        let comment = "//.*?\n";
        let comments = r"/\*[\s\S\n]+?\*/";
        let pattern = format!("({comment})|({comments})|({keywords})|({symbols})|({str_pattern})|({id_pattern})|(\\d+)");
        return Tokenizer {
            re: Regex::new(&pattern).expect("regex syntax error."),
        };
    }

    pub fn tokenize(&self, input: &Path) -> Vec<Token> {
        let mut f = fs::File::open(input).unwrap();
        let mut text = String::new();
        f.read_to_string(&mut text).unwrap();
        return self
            .re
            .captures_iter(&text)
            .map(|cap| -> Token {
                if let Some(kw) = cap.get(3) {
                    return Token::Keyword(kw.as_str().to_string());
                } else if let Some(sm) = cap.get(4) {
                    return Token::Symbol(sm.as_str().to_string());
                } else if let Some(s) = cap.get(5) {
                    let r = s.as_str();
                    return Token::StringConstant(r[1..r.len() - 1].to_string());
                } else if let Some(id) = cap.get(6) {
                    return Token::Identifier(id.as_str().to_string());
                } else if let Some(digits) = cap.get(7) {
                    return Token::IntegerConstant(str::parse::<u32>(digits.as_str()).unwrap());
                } else {
                    return Token::Invalid;
                }
            })
            .filter(|t| -> bool { !matches!(t, Token::Invalid) })
            .collect();
    }
}
