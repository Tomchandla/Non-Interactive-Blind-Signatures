use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Run the Makefile to build the proof system for MAYO
    let status = Command::new("make").status().expect("Failed to run make");

    if !status.success() {
        panic!("Makefile execution failed");
    }
    println!("cargo:rustc-link-search=target/debug");
    println!("cargo:rustc-link-lib=consv_bs_rainhash");

    println!("cargo:rerun-if-changed=wrapper.h");
    // Rebuild (and relink dependants) whenever the circuit sources change.
    println!("cargo:rerun-if-changed=../vole/conservative_bs");
    println!("cargo:rerun-if-changed=../vole/build_consv_bs_rainhash.sh");
    println!("cargo:rerun-if-changed=../vole/meson.build");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-I../vole/conservative_bs")
        .generate()
        .expect("Unable to generate bindings");

    // Write bindings to file
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
