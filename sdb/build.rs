use std::fs;
use std::path::{Path};


const WRAPPER_H: &str = "src/libsdb/wrapper.h";
const BINDINGS_RS: &str = "src/libsdb/bindings.rs";

fn newer(src: &Path, dst: &Path) -> bool {
    match (fs::metadata(src), fs::metadata(dst)) {
        (Ok(s), Ok(d)) => s.modified().unwrap() > d.modified().unwrap(),
        _ => true, // if either file missing, rebuild
    }
}

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

fn main() {
    generate_bindings();
}
