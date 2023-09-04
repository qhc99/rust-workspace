#![allow(clippy::needless_return)]
use std::{
    cmp::Ordering,
    env,
    fs::{self},
    io::{self, Error},
    path::{Path, PathBuf},
};

use code_writer::CodeWriter;
use command_type::CommandType;
use parser::Parser;
mod code_writer;
mod command_type;
mod parser;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Arg num should be 1");
    }
    let input_path: &str = &args[1];
    let input_path = Path::new(input_path);
    if !input_path.exists() {
        panic!("input file not exists")
    }
    if input_path.is_dir() {
        let out_path = output_to_dir_path(input_path);
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
        if input_path
            .extension()
            .ok_or(Error::new(io::ErrorKind::InvalidInput, "file no ext"))?
            .to_str()
            .ok_or(Error::new(
                io::ErrorKind::InvalidInput,
                "cannot convert os str",
            ))?
            != "vm"
        {
            panic!("input file is not ends with .vm");
        } else {
            let out_path = replace_extension_path(input_path);
            let mut parser = Parser::new(&input_path.to_path_buf())?;
            let mut writer = CodeWriter::new(&out_path);
            translate(&mut parser, &mut writer)?;
        }
    } else {
        panic!("input path is not dir or file");
    }
    return Ok(());
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

fn output_to_dir_path(path: &Path) -> PathBuf {
    let mut new_path = PathBuf::new();
    new_path.push(path);
    if let Some(stem) = path.file_name() {
        new_path.push(stem);
    }
    new_path.set_extension("asm");
    new_path
}