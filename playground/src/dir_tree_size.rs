use std::env;
use std::ffi::OsStr;
use std::fs::{self};
use std::path::Path;
use rust_libs::f_loc;
use rust_libs::utils::MapErrMsg;

fn get_folder_size(path: &Path) -> std::io::Result<u64> {
    let mut size = 0;

    // Traverse the directory entries recursively
    for entry in fs::read_dir(path).log_err(f_loc!())? {
        let entry = entry.log_err(f_loc!())?;
        let path = entry.path();
        if path.is_dir() {
            // If it's a directory, recursively get its size
            size += get_folder_size(&path).log_err(f_loc!())?;
        } else {
            // Sum up the size of each file
            size += entry.metadata().log_err(f_loc!())?.len();
        }
    }
    Ok(size)
}

pub fn main() -> std::io::Result<()> {
    let mut args: Vec<String> = env::args().collect();
    let mut input: String = String::new();
    if args.len() == 2 {
        // The first argument is the program itself, so the second one (index 1) is the first user-provided argument
        input = args.pop().unwrap();
        println!("Path: {}", input);
    } else {
        println!("No arguments were provided.");
    }

    let path = Path::new(&input);
    if !fs::read_dir(path).is_ok() {
        println!("Input is not a folder.");
        return Ok(());
    }
    
    let mut folder_size_arr = Vec::<(String, u64)>::new();
    for entry in fs::read_dir(path).log_err(f_loc!())? {
        let entry = entry.log_err(f_loc!())?;
        let path = entry.path();

        if path.is_dir() {
            // If it's a directory, recursively get its size
            _ = get_folder_size(&path).and_then(|s| {
                path.file_name().and_then(|n| {
                    folder_size_arr.push((n.to_str()?.to_string(), s));
                    None::<&OsStr>
                });
                Ok(())
            }).log_err(&format!("Cannot read {:?}",path.file_name()));
        } else {
            // Sum up the size of each file
            entry.metadata().and_then(|m| {
                path.file_name().and_then(|n| {
                    folder_size_arr.push((n.to_str()?.to_string(), m.len()));
                    None::<&OsStr>
                });
                Ok(())
            })?;
        }
    }
    folder_size_arr.sort_by(|a, b| a.1.cmp(&b.1));
    for i in folder_size_arr{
        println!("{}: {} bytes", i.0, i.1);
    }
    Ok(())
}
