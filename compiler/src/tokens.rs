
#[derive(Debug)]
pub enum Token{
    Keyword(String),
    Symbol(String),
    IntegerConstant(u32),
    StringConstant(String),
    Identifier(String),
    Invalid
}