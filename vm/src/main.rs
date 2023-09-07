#![allow(clippy::needless_return)]
use std::{
    collections::HashSet,
    env,
    fs::{self},
    io::{self, Error},
    path::{Path, PathBuf},
};

use std::{
    fs::File,
    io::{BufRead, BufReader},
    iter::Peekable,
};

use std::io::Write;

pub struct CodeWriter {
    out: File,
    input_file_name: String,
    cond_label_num: u16,
    if_goto_num: u16,
    func_call_ret_num: u16,
    func_clean_lcl_num: u16,
}

impl CodeWriter {
    pub fn new(out_path: &PathBuf) -> Self {
        let out = File::create(out_path).expect("cannot create output file");

        CodeWriter {
            out,
            input_file_name: "".to_string(),
            cond_label_num: 0,
            if_goto_num: 0,
            func_call_ret_num: 0,
            func_clean_lcl_num: 0,
        }
    }

    pub fn reset_input_metadata(&mut self, in_name: &str) {
        self.input_file_name = in_name.to_string();
        self.cond_label_num = 0;
        self.if_goto_num = 0;
        self.func_call_ret_num = 0;
        self.func_clean_lcl_num = 0;
    }

    pub fn write_arithmetic(&mut self, cmd: String) {
        match cmd.as_str() {
            "add" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D+M // add",
                );
            }
            "sub" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=M-D // sub",
                );
            }
            "neg" => {
                self.write(
                    "
@0 // neg
A=M-1
M=-M",
                );
            }
            "eq" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare("JEQ");
            }
            "gt" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare("JGT");
            }
            "lt" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare("JLT");
            }
            "and" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D&M // and",
                )
            }
            "or" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D|M // or",
                );
            }
            "not" => {
                self.write(
                    "
@0
A=M-1
M=!M // not",
                );
            }
            other => {
                panic!("unmatched arithmetic cmd: {}", other)
            }
        }
    }

    // write string with \n at head and after every line except the last line
    fn write(&mut self, data: &str) {
        self.out
            .write_all(data.as_bytes())
            .expect("cannot write to output file");
    }

    fn gen_partial_compare(&mut self, j: &str) {
        self.write(&format!(
            "
D=M-D
@{0}$cond$true.{1}
D;{2} // {2} to true
@0
A=M-1
M=0
@{0}$cond$false.{1}
0;JMP // JMP to false
({0}$cond$true.{1})
@0
A=M-1
M=-1
({0}$cond$false.{1})",
            self.input_file_name, self.cond_label_num, j
        ));
        self.cond_label_num += 1;
    }

    /// SP <- SP-1, A <- SP-1 D <- RAM[SP], A <- SP-1
    fn gen_arithmetic_double_partial(&mut self) {
        self.out
            .write_all(
                "
@0 // arithmetic double operaotr
AM=M-1
D=M
A=A-1"
                    .as_bytes(),
            )
            .unwrap();
    }

    pub fn write_push(&mut self, seg: &str, idx: i16) {
        match seg {
            "local" => self.write_base_shift_push(1, idx, true),
            "argument" => self.write_base_shift_push(2, idx, true),
            "this" => self.write_base_shift_push(3, idx, true),
            "that" => self.write_base_shift_push(4, idx, true),
            "constant" => self.write_reg_a_push(&idx.to_string(), true),
            "static" => {
                self.write_reg_a_push(&format!("{0}.{1}", self.input_file_name, idx), false)
            }
            "temp" => self.write_base_shift_push(5, idx, false),
            "pointer" => self.write_base_shift_push(3, idx, false),
            _ => {
                panic!("unknown push stack segment")
            }
        }
    }

    fn write_reg_a_push(&mut self, a: &str, immediate: bool) {
        self.write(&format!(
            "
@{0} // push reg {a}, {immediate}
D={1}
@0
A=M
M=D
@0
M=M+1",
            a,
            if immediate { "A" } else { "M" }
        ))
    }

    fn write_base_shift_push(&mut self, base: i16, shift: i16, indirect: bool) {
        self.write(&format!(
            "
@{0} // push {base} {shift}, {2}
D={2}
@{1}
A=D+A
D=M
@0
A=M
M=D
@0
M=M+1",
            base,
            shift,
            if indirect { "M" } else { "A" }
        ))
    }

    fn write_base_shift_pop(&mut self, base: i16, shift: i16, indirect: bool) {
        self.write(&format!(
            "
@0 // pop {base} {shift}, {2}
AM=M-1
D=M
@R13 // RAM[R13] = val
M=D
@{0}
D={2}
@{1}
D=D+A
@R14 // RAM[R14] = addr
M=D
@R13
D=M
@R14
A=M
M=D",
            base,
            shift,
            if indirect { "M" } else { "A" }
        ))
    }

    pub fn write_pop(&mut self, seg: &str, idx: i16) {
        match seg {
            "local" => self.write_base_shift_pop(1, idx, true),
            "argument" => self.write_base_shift_pop(2, idx, true),
            "this" => self.write_base_shift_pop(3, idx, true),
            "that" => self.write_base_shift_pop(4, idx, true),
            "constant" => self.write(
                "
@0 // pop constant
M=M-1",
            ),
            "static" => self.write(&format!(
                "
@0 // pop static 
AM=M-1
D=M
@{0}.{1} // var name
M=D",
                self.input_file_name, idx
            )),
            "temp" => self.write_base_shift_pop(5, idx, false),
            "pointer" => self.write_base_shift_pop(3, idx, false),
            _ => {
                panic!("unknown push stack segment")
            }
        }
    }

    pub fn write_label(&mut self, arg1: &str) {
        self.write(&format!(
            "
({})",
            arg1
        ))
    }

    pub fn write_goto(&mut self, arg1: &str) {
        self.write(&format!(
            "
@{} // goto
0;JMP",
            arg1
        ))
    }

    pub fn write_if_goto(&mut self, arg1: &str) {
        self.write(&format!(
            "
@0 // if-goto {arg1}
AM=M-1
D=M
@{0}$if-goto$false.{1}
D;JEQ
@{2}
0;JMP
({0}$if-goto$false.{1})",
            self.input_file_name, self.if_goto_num, arg1
        ));
        self.if_goto_num += 1;
    }

    pub fn write_function(&mut self, func_name: &str, lcl: i16) {
        self.write(&format!(
            "
({0}$entry) // function {0} {1}
@0
D=M
@1
M=D // load lcl
@{1}
D=D+A
@R13
M=D // RAM[R13] = stop SP
({2}$clear-lcl-loop.{3})
@R13
D=M
@0
D=D-M
@{2}$clear-lcl-stop.{3}
D;JEQ 
@0
A=M
M=0
@0
M=M+1
@{2}$clear-lcl-loop.{3}
0;JMP
({2}$clear-lcl-stop.{3})",
            func_name, lcl, self.input_file_name, self.func_clean_lcl_num
        ));
        self.func_clean_lcl_num += 1;
    }

    pub fn write_call(&mut self, func_name: &str, arg: i16) {
        self.write(&format!(
            "
@0 // call {func_name} {arg}
D=M
@{0} // arg num
D=D-A
@R13
M=D // wait to load arg
@{2}$ret.{3}
D=A
@0
A=M
M=D // save return jump line
@0
M=M+1
@1
D=M
@0
A=M
M=D // save LCL
@0
M=M+1
@2
D=M
@0
A=M
M=D // save arg 
@0
M=M+1
@3
D=M
@0
A=M
M=D // save this
@0
M=M+1
@4
D=M
@0
A=M
M=D // save that
@0
M=M+1
@R13
D=M
@2
M=D // load arg
@{1}$entry
0;JMP
({2}$ret.{3})",
            arg, func_name, self.input_file_name, self.func_call_ret_num
        ));
        self.func_call_ret_num += 1;
    }

    pub fn write_return(&mut self) {
        self.write(
            "
@0 // return
AM=M-1
D=M
@R13
M=D // RAM[R13] = ret
@1
D=M-1
@0
M=D // SP = LCL-1
@0
A=M
D=M
@4
M=D // reload that
@0
AM=M-1
D=M 
@3
M=D // reload this
@0
M=M-1
@2
D=M
@R14
M=D // RAM[R14] = arg
@0
A=M
D=M
@2
M=D // reload arg
@0
AM=M-1
D=M
@1
M=D // reload lcl
@0
A=M-1
D=M
@R15
M=D // RAM[R15] = jump
@R14
D=M
@0
M=D // reload stack base
@R13
D=M
@0
A=M
M=D // set return value
@0
M=M+1
@R15
A=M
0;JMP // return jump",
        )
    }

    pub fn write_sys_init(&mut self) {
        self.write(
            "
@256
D=A
@0
M=D
@11111
D=A
@1
M=D
@22222
D=A
@2
M=D
@33333
D=A
@3
M=D
@44444
D=A
@4
M=D
",
        );
        self.write_call("Sys.init", 0);
    }
}

#[derive(PartialEq, Eq)]
pub enum CommandType {
    Arithmetic,
    Push,
    Pop,
    Label,
    Goto,
    If,
    Function,
    Return,
    Call,
}
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Arg num should be 1");
    }
    let input_path: &str = &args[1];
    let input_path = Path::new(input_path);
    if !input_path.exists() {
        panic!("input path not exists")
    }
    compile(input_path)?;
    // compile_all_dirs()?;
    Ok(())
}

fn compile_all_dirs() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Arg num should be 1");
    }
    let input_path: &str = &args[1];
    let input_path = Path::new(input_path);
    if !input_path.exists() {
        panic!("input path not exists")
    }
    if input_path.is_dir() {
        let mut compile_dirs = HashSet::<PathBuf>::new();
        find_compile_dirs(input_path, &mut compile_dirs)?;
        for compile_dir in compile_dirs {
            compile(compile_dir.as_path())?;
        }
    } else {
        panic!("input path is not a dir");
    }

    Ok(())
}

fn find_compile_dirs(dir: &Path, sets: &mut HashSet<PathBuf>) -> Result<(), std::io::Error> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Recursively visit subdirectories
                find_compile_dirs(&path, sets)?;
            } else if path
                .extension()
                .map_or(false, |p| -> _ { p.to_str().unwrap() == "vm" })
            {
                sets.insert(path.parent().unwrap().to_owned());
            }
        }
    }
    Ok(())
}

fn compile(input_path: &Path) -> io::Result<()> {
    if input_path.is_dir() {
        let out_path = output_to_dir_path(input_path);
        println!("generate: {}", out_path.to_str().unwrap());
        let mut writer = CodeWriter::new(&out_path);
        let t = fs::read_dir(input_path)?;
        let mut bootstrap = false;
        let mut vm_f_paths = Vec::<PathBuf>::new();
        for f in t {
            let f = f?;
            if f.file_type()?.is_file()
                && f.file_name()
                    .to_str()
                    .map(|s: &str| -> _ { s.ends_with(".vm") })
                    == Some(true)
            {
                let p = f.path();
                if p.file_stem().unwrap().to_str().unwrap() == "Sys" {
                    bootstrap = true;
                }
                vm_f_paths.push(p);
            }
        }
        if bootstrap {
            writer.write_sys_init();
        }
        for p in vm_f_paths.iter() {
            let mut parser = Parser::new(p)?;
            translate(&mut parser, &mut writer)?;
        }
    } else if input_path.is_file() {
        if !(input_path
            .extension()
            .ok_or(Error::new(io::ErrorKind::InvalidInput, "file no ext"))?
            .to_str()
            .ok_or(Error::new(
                io::ErrorKind::InvalidInput,
                "cannot convert os str",
            ))?
            == "vm")
        {
            panic!("input file is not ends with .vm");
        } else {
            let out_path = replace_extension_path(input_path);
            let mut parser = Parser::new(&input_path.to_path_buf())?;
            let mut writer = CodeWriter::new(&out_path);
            translate(&mut parser, &mut writer)?;
        }
    } else {
        panic!("input path is not a dir");
    }
    return Ok(());
}

fn replace_extension_path(path: &Path) -> PathBuf {
    let mut new_path = PathBuf::new();
    if let Some(parent) = path.parent() {
        new_path.push(parent);
    }
    if let Some(stem) = path.file_stem() {
        new_path.push(stem);
    }
    new_path.set_extension("asm");
    new_path
}

fn translate(parser: &mut Parser, writer: &mut CodeWriter) -> io::Result<()> {
    writer.reset_input_metadata(parser.file_name());
    while parser.has_more_commands() {
        parser.advance()?;
        let cmd_type = parser.command_type();

        match cmd_type {
            CommandType::Arithmetic => {
                writer.write_arithmetic(parser.raw_cmd());
            }
            CommandType::Push => {
                let arg1 = parser.arg1();
                let arg2 = parser.arg2();
                writer.write_push(&arg1, arg2);
            }
            CommandType::Pop => {
                let arg1 = parser.arg1();
                let arg2 = parser.arg2();
                writer.write_pop(&arg1, arg2);
            }
            CommandType::Label => {
                let arg1 = parser.arg1();
                writer.write_label(&arg1);
            }
            CommandType::Goto => {
                let arg1 = parser.arg1();
                writer.write_goto(&arg1);
            }
            CommandType::If => {
                let arg1 = parser.arg1();
                writer.write_if_goto(&arg1);
            }
            CommandType::Function => {
                let arg1 = parser.arg1();
                let arg2 = parser.arg2();
                writer.write_function(&arg1, arg2);
            }
            CommandType::Return => {
                writer.write_return();
            }
            CommandType::Call => {
                let arg1 = parser.arg1();
                let arg2 = parser.arg2();
                writer.write_call(&arg1, arg2);
            }
        }
    }
    Ok(())
}

fn output_to_dir_path(path: &Path) -> PathBuf {
    let mut new_path = PathBuf::new();
    new_path.push(path);
    if let Some(stem) = path.file_name() {
        new_path.push(stem);
    }
    new_path.set_extension("asm");
    new_path
}

pub struct Parser {
    cmd_iter: Peekable<Box<dyn Iterator<Item = io::Result<String>>>>,
    cmd: Option<String>,
    arg1: Option<String>,
    arg2: Option<i16>,
    file_name: String,
}

impl Parser {
    pub fn new(input_path: &PathBuf) -> io::Result<Self> {
        let file_name = input_path
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let lines = BufReader::new(File::options().read(true).open(input_path)?).lines();
        let iter = lines
            .map(|r| -> _ { r.map(|s| -> _ { Self::strip_comment(&s).trim().to_string() }) })
            .filter(|r| -> bool { r.as_ref().map_or(false, |s| -> _ { !s.is_empty() }) });
        let b: Box<dyn Iterator<Item = io::Result<String>>> = Box::new(iter);
        Ok(Self {
            cmd_iter: b.peekable(),
            cmd: None,
            arg1: None,
            arg2: None,
            file_name,
        })
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn has_more_commands(&mut self) -> bool {
        return self.cmd_iter.peek().is_some();
    }

    pub fn advance(&mut self) -> io::Result<()> {
        let s = self
            .cmd_iter
            .next()
            .expect("advance called when no more commands");
        let s = s?;
        let mut l = s.split(" ").filter(|s| -> _ { !s.is_empty() });
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

    pub fn raw_cmd(&mut self) -> String {
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
