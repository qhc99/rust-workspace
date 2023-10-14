use std::{fs::File, io::Write, path::PathBuf};

use crate::sym_table::VarType;

#[derive(Debug, Display)]
pub enum Segment {
    #[display(fmt = "constant")]
    Const,
    #[display(fmt = "argument")]
    Arg,
    #[display(fmt = "local")]
    Local,
    #[display(fmt = "static")]
    Static,
    #[display(fmt = "this")]
    This,
    #[display(fmt = "that")]
    That,
    #[display(fmt = "pointer")]
    Pointer,
    #[display(fmt = "temp")]
    Temp,
}

impl From<&VarType> for Segment {
    fn from(kind: &VarType) -> Self {
        match kind {
            VarType::Static => Segment::Static,
            VarType::Field => Segment::This,
            VarType::Arg => Segment::Arg,
            VarType::Var => Segment::Local,
            VarType::None => panic!(),
        }
    }
}

#[derive(Debug, Display)]
pub enum Command {
    #[display(fmt = "add")]
    Add,
    #[display(fmt = "sub")]
    Sub,
    #[display(fmt = "neg")]
    Neg,
    #[display(fmt = "eq")]
    Eq,
    #[display(fmt = "gt")]
    Gt,
    #[display(fmt = "lt")]
    Lt,
    #[display(fmt = "and")]
    And,
    #[display(fmt = "or")]
    Or,
    #[display(fmt = "not")]
    Not,
}

pub struct CodeGenerator {
    out: File,
}

impl CodeGenerator {
    pub fn new(out: &str) -> Self {
        let p = PathBuf::from(out);
        if p.exists() {
            let f = File::create(p).unwrap();
            CodeGenerator { out: f }
        } else {
            panic!()
        }
    }

    fn write(&mut self, data: &str) {
        self.out
            .write_all(data.as_bytes())
            .expect("cannot write to output file");
    }

    pub fn write_push(&mut self, seg: &Segment, idx: u32) {
        self.write(&format!("push {seg} {idx}\n"));
    }

    pub fn write_pop(&mut self, seg: &Segment, idx: u32) {
        self.write(&format!("pop {seg} {idx}\n"));
    }

    pub fn write_arithmetic(&mut self, cmd: &Command) {
        self.write(&format!("{cmd}\n"));
    }

    pub fn write_label(&mut self, label: &str) {
        self.write(&format!("label {label}\n"));
    }

    pub fn write_goto(&mut self, label: &str) {
        self.write(&format!("goto {label}\n"));
    }

    pub fn write_if(&mut self, label: &str) {
        self.write(&format!("if-goto {label}\n"));
    }

    pub fn write_call(&mut self, name: &str, n_args: u32) {
        self.write(&format!("call {name} {n_args}\n"));
    }

    pub fn write_function(&mut self, name: &str, n_locals: u32) {
        self.write(&format!("function {name} {n_locals}\n"));
    }

    pub fn write_return(&mut self) {
        self.write("return\n");
    }
}
