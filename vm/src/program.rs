use std::{
    collections::HashSet,
    env, fs,
    io::{self, Error},
    path::{Path, PathBuf},
};

use crate::{code_writer::CodeWriter, command_type::CommandType, parser::Parser};

pub fn compile_single_file() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Arg num should be 1");
    }
    let input_path: &str = &args[1];
    let input_path = Path::new(input_path);
    if !input_path.exists() {
        panic!("input path not exists")
    }
    compile(input_path).unwrap();
}

#[allow(dead_code)]
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

pub fn compile(input_path: &Path) -> io::Result<()> {
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
