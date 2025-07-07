// build.rs
fn main() {
    println!("cargo:rerun-if-changed=src/libsdb/wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("src/libsdb/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file("src/libsdb/bindings.rs")
        .expect("Couldn't write bindings!");
}
