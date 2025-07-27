#![cfg(test)]
use std::env;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
pub struct BinBuilder {
    output_path: PathBuf,
    so_paths: Vec<PathBuf>,
}
static GLOBAL_COUNT: AtomicI32 = AtomicI32::new(0);

impl BinBuilder {
    pub fn rustc(dir: &str, source: &str) -> Self {
        let current_dir = PathBuf::from(dir);
        let suffix = GLOBAL_COUNT.fetch_add(1, Ordering::SeqCst);
        let output_name = source.strip_suffix(".rs").unwrap();
        let output_name = format!("{output_name}_{suffix}");
        let status = Command::new("rustc")
            .args(&[source, "-o", &output_name])
            .current_dir(&current_dir)
            .status()
            .expect("Failed to run rustc");
        assert!(status.success(), "Compilation failed");
        let mut output_path = current_dir.clone();
        output_path.push(output_name);
        BinBuilder {
            output_path,
            so_paths: Vec::new(),
        }
    }

    pub fn asm(dir: &str, source: &str) -> Self {
        let current_dir = PathBuf::from(dir);
        let suffix = GLOBAL_COUNT.fetch_add(1, Ordering::SeqCst);
        let output_name = source.strip_suffix(".s").unwrap();
        let output_name = format!("{output_name}_{suffix}");
        let status = Command::new("gcc")
            .args(&["-pie", "-o", &output_name, source])
            .current_dir(&current_dir)
            .status()
            .expect("Failed to run gcc");
        assert!(status.success(), "Compilation failed");
        let mut output_path = current_dir.clone();
        output_path.push(output_name);
        BinBuilder {
            output_path,
            so_paths: Vec::new(),
        }
    }

    pub fn cpp(dir: &str, source: &[&str]) -> Self {
        let current_dir = PathBuf::from(dir);
        let suffix = GLOBAL_COUNT.fetch_add(1, Ordering::SeqCst);
        let output_name = source.first().unwrap().strip_suffix(".cpp").unwrap();
        let output_name = format!("{output_name}_{suffix}");
        let mut cmd = Command::new("g++");
        cmd.args(&{
            let mut ret = source.to_vec();
            ret.extend_from_slice(&["-pie", "-g", "-O0", "-gdwarf-4", "-o", &output_name]);
            ret
        })
        .current_dir(&current_dir);
        let status = cmd.status().expect("Failed to run g++");
        assert!(status.success(), "Compilation failed");
        let mut output_path = current_dir.clone();
        output_path.push(output_name);
        BinBuilder {
            output_path,
            so_paths: Vec::new(),
        }
    }

    pub fn cpp_with_so(dir: &str, sources: &[&str], libs: &[&str]) -> Self {
        let current_dir = PathBuf::from(dir);
        let suffix = GLOBAL_COUNT.fetch_add(1, Ordering::SeqCst);

        let so_names = libs
            .iter()
            .map(|lib| {
                let so_name = lib.strip_suffix(".cpp").unwrap();
                format!("{so_name}_{suffix}")
            })
            .collect::<Vec<_>>();
        for lib in libs {
            let mut cmd = Command::new("g++");
            let name = lib.strip_suffix(".cpp").unwrap();
            let o_with_suffix = format!("{name}_{suffix}.o");
            cmd.args(&[
                "-fPIC",
                "-g",
                "-O0",
                "-gdwarf-4",
                "-c",
                lib,
                "-o",
                &o_with_suffix,
            ])
            .current_dir(&current_dir)
            .status()
            .expect("Failed to run build .o");

            let lib_name = format!("lib{name}_{suffix}.so");
            let mut cmd = Command::new("g++");
            cmd.args(&[
                "-g",
                "-O0",
                "-gdwarf-4",
                "-shared",
                "-o",
                &lib_name,
                &o_with_suffix,
            ])
            .current_dir(&current_dir)
            .status()
            .expect("Failed to run .so");
        }
        let l_args = so_names
            .iter()
            .map(|so_name| format!("-l{so_name}"))
            .collect::<Vec<String>>();

        let output_name = sources.first().unwrap().strip_suffix(".cpp").unwrap();
        let output_name = format!("{output_name}_{suffix}");
        let mut cmd = Command::new("g++");
        cmd.args(&{
            let mut ret = sources.to_vec();
            ret.extend_from_slice(&["-pie", "-g", "-O0", "-gdwarf-4", "-L.", "-o", &output_name]);
            ret.extend_from_slice(&l_args.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
            ret
        })
        .current_dir(&current_dir);
        let status = cmd.status().expect("Failed to build bin");
        assert!(status.success(), "Compilation failed");

        let mut so_paths = Vec::new();
        for lib in libs {
            let mut cmd = Command::new("rm");
            let name = lib.strip_suffix(".cpp").unwrap();
            let o_file = format!("{name}_{suffix}.o");
            cmd.args(&["-f", &o_file]);
            cmd.current_dir(&current_dir)
                .status()
                .expect("Failed to run rm");

            let so_file = format!("lib{name}_{suffix}.so");
            let mut output_path = current_dir.clone();
            output_path.push(so_file);
            so_paths.push(output_path);
        }

        let mut output_path = current_dir.clone();
        output_path.push(output_name);
        BinBuilder {
            output_path,
            so_paths,
        }
    }

    pub fn target_path(&self) -> &Path {
        self.output_path.as_path()
    }
}

impl Drop for BinBuilder {
    fn drop(&mut self) {
        if self.output_path.exists() {
            if let Err(e) = fs::remove_file(&self.output_path) {
                eprintln!("Failed to delete binary {:?}: {}", self.output_path, e);
            }
        }
        for so_path in &self.so_paths {
            if let Err(e) = fs::remove_file(&so_path) {
                eprintln!("Failed to delete shared object {:?}: {}", so_path, e);
            }
        }
    }
}

static LD_PATH_LOCK: Mutex<()> = Mutex::new(());

pub fn append_ld_dir(dir: &str) {
    let _guard = LD_PATH_LOCK.lock().unwrap();
    let mut ld_path = env::var("LD_LIBRARY_PATH").unwrap_or_default();
    if !ld_path.split(':').any(|p| p == dir) {
        ld_path.push(':');
        ld_path.push_str(dir);
    }
    unsafe { env::set_var("LD_LIBRARY_PATH", ld_path) };
}

#[ignore = "Manual"]
#[test]
fn build_marshmallow() {
    BinBuilder::cpp_with_so("resource", &["marshmallow.cpp"], &["meow.cpp"]);
}
