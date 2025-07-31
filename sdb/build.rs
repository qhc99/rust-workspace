// build.rs – build‑time helpers for tests & bindgen
//
// * **Generates** `src/libsdb/bindings.rs` when `wrapper.h` is newer.
// * **Pre‑builds** helper binaries / shared objects into `resource/bin/`,
//   recompiling only when sources are newer.
// * `cargo:rerun-if-changed` is emitted for every tracked file.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ------------------------------- configuration ----------------------------
const RESOURCE_DIR: &str = "resource";
const BIN_SUBDIR: &str = "bin"; // executables & .so files live here

const RUST_SOURCES: &[&str] = &["loop_assign.rs", "just_exit.rs"];
const ASM_SOURCES: &[&str] = &["reg_write.s", "reg_read.s"];
// (exe sources, shared‑lib sources)
const CPP_TARGETS: &[(&[&str], &[&str])] = &[
    (&["hello_sdb.cpp"], &[]),
    (&["memory.cpp"], &[]),
    (&["anti_debugger.cpp"], &[]),
    (&["multi_threaded.cpp"], &[]),
    (&["step.cpp"], &[]),
    (&["multi_cu_main.cpp", "multi_cu_other.cpp"], &[]),
    (&["overloaded.cpp"], &[]),
    (&["marshmallow.cpp"], &["meow.cpp"]),
];
const WRAPPER_H: &str = "src/libsdb/wrapper.h";
const BINDINGS_RS: &str = "src/libsdb/bindings.rs";
// -------------------------------------------------------------------------

// ------------------------------- utilities --------------------------------
fn ensure_bin_dir() {
    let bin = Path::new(RESOURCE_DIR).join(BIN_SUBDIR);
    if !bin.exists() {
        fs::create_dir_all(&bin).expect("cannot create resource/bin directory");
    }
}

fn bin_path(name: &str) -> PathBuf {
    Path::new(RESOURCE_DIR).join(BIN_SUBDIR).join(name)
}

fn newer(src: &Path, dst: &Path) -> bool {
    match (fs::metadata(src), fs::metadata(dst)) {
        (Ok(s), Ok(d)) => s.modified().unwrap() > d.modified().unwrap(),
        _ => true, // if either file missing, rebuild
    }
}
// -------------------------------------------------------------------------

// ------------------------ individual build steps --------------------------
fn generate_bindings() {
    println!("cargo:rerun-if-changed={WRAPPER_H}");
    let wrapper = Path::new(WRAPPER_H);
    let bindings = Path::new(BINDINGS_RS);

    if !bindings.exists() || newer(wrapper, bindings) {
        println!("cargo:warning=Regenerating {wrapper:?} → {bindings:?}");
        let out = bindgen::Builder::default()
            .header(WRAPPER_H)
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate bindings");
        out.write_to_file(bindings)
            .expect("Couldn't write bindings!");
    }
}

fn compile_rust(src: &str) {
    let src_path = Path::new(RESOURCE_DIR).join(src);
    let stem = src_path.file_stem().unwrap().to_string_lossy();
    let bin_path_full = bin_path(&stem);
    let bin_rel = format!("{BIN_SUBDIR}/{stem}"); // relative to RESOURCE_DIR

    if !bin_path_full.exists() || newer(&src_path, &bin_path_full) {
        println!("cargo:warning=Compiling {src} → {bin_rel}");
        Command::new("rustc")
            .current_dir(RESOURCE_DIR)
            .args([src, "-o", &bin_rel])
            .status()
            .expect("rustc failed");
    }
    println!("cargo:rerun-if-changed={}", src_path.display());
}

fn compile_asm(src: &str) {
    let src_path = Path::new(RESOURCE_DIR).join(src);
    let stem = src_path.file_stem().unwrap().to_string_lossy();
    let bin_path_full = bin_path(&stem);
    let bin_rel = format!("{BIN_SUBDIR}/{stem}");

    if !bin_path_full.exists() || newer(&src_path, &bin_path_full) {
        println!("cargo:warning=Compiling {src} → {bin_rel}");
        Command::new("gcc")
            .current_dir(RESOURCE_DIR)
            .args(["-pie", "-o", &bin_rel, src])
            .status()
            .expect("gcc failed");
    }
    println!("cargo:rerun-if-changed={}", src_path.display());
}

fn compile_cpp(sources: &[&str], libs: &[&str]) {
    // 1. Shared objects --------------------------------------------------
    for lib in libs {
        let src = Path::new(RESOURCE_DIR).join(lib);
        let stem = src.file_stem().unwrap().to_string_lossy();
        let so_name = format!("lib{stem}.so");
        let so_path_full = bin_path(&so_name);
        let so_rel = format!("{BIN_SUBDIR}/{so_name}");
        let obj_rel = format!("{BIN_SUBDIR}/{stem}.o");

        if !so_path_full.exists() || newer(&src, &so_path_full) {
            // compile .o then .so
            Command::new("g++")
                .current_dir(RESOURCE_DIR)
                .args(["-fPIC", "-g", "-O0", "-gdwarf-4", "-c", lib, "-o", &obj_rel])
                .status()
                .expect("g++ object build failed");
            Command::new("g++")
                .current_dir(RESOURCE_DIR)
                .args(["-g", "-O0", "-gdwarf-4", "-shared", "-o", &so_rel, &obj_rel])
                .status()
                .expect("g++ shared build failed");
        }
        println!("cargo:rerun-if-changed={}", src.display());
    }

    // 2. Executable ------------------------------------------------------
    let stem = Path::new(sources[0]).file_stem().unwrap().to_string_lossy();
    let exe_path_full = bin_path(&stem);
    let exe_rel = format!("{BIN_SUBDIR}/{stem}");

    let needs_rebuild = !exe_path_full.exists()
        || sources
            .iter()
            .any(|s| newer(&Path::new(RESOURCE_DIR).join(s), &exe_path_full))
        || libs.iter().any(|l| {
            let so_name = format!(
                "lib{}.so",
                Path::new(l).file_stem().unwrap().to_string_lossy()
            );
            newer(&bin_path(&so_name), &exe_path_full)
        });

    if needs_rebuild {
        println!("cargo:warning=Compiling {sources:?} → {exe_rel}");
        let mut args: Vec<String> = sources.iter().map(|s| s.to_string()).collect(); // relative names
        args.extend(
            ["-pie", "-g", "-O0", "-gdwarf-4", "-L./bin", "-o", &exe_rel]
                .iter()
                .map(|s| s.to_string()),
        );
        for lib in libs {
            let stem = Path::new(lib).file_stem().unwrap().to_string_lossy();
            args.push(format!("-l{stem}"));
        }
        Command::new("g++")
            .current_dir(RESOURCE_DIR)
            .args(&args)
            .status()
            .expect("g++ exe build failed");
    }

    for s in sources {
        println!("cargo:rerun-if-changed={RESOURCE_DIR}/{s}");
    }
}
// -------------------------------------------------------------------------

fn main() {
    generate_bindings();
    ensure_bin_dir();

    for src in RUST_SOURCES {
        compile_rust(src);
    }
    for src in ASM_SOURCES {
        compile_asm(src);
    }
    for (srcs, libs) in CPP_TARGETS {
        compile_cpp(srcs, libs);
    }
}
