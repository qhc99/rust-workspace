#![cfg(test)]
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicI32, Ordering};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
pub struct BinBuilder {
    output_path: PathBuf,
}
static GLOBAL_COUNT: Lazy<AtomicI32> = Lazy::new(|| AtomicI32::new(0));

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
        BinBuilder { output_path }
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
        BinBuilder { output_path }
    }

    pub fn target_path(&self) -> &Path {
        self.output_path.as_path()
    }
}

impl Drop for BinBuilder {
    fn drop(&mut self) {
        if self.output_path.exists() {
            if let Err(e) = fs::remove_file(&self.output_path) {
                log::error!("Failed to delete binary {:?}: {}", self.output_path, e);
            }
        }
    }
}
