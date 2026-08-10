use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Run the Makefile to build MAYO and XKCP
    let status = Command::new("make").status().expect("Failed to run make");

    if !status.success() {
        panic!("Makefile execution failed");
    }
    // Specify the library search paths for MAYO
    println!("cargo:rustc-link-search=target/debug");
    // Specify the library search paths for MAYO
    println!("cargo:rustc-link-search=../vole-rainhash-then-mayo-sys/target/debug");

    // Specify the libraries to link
    println!("cargo:rustc-link-lib=mayo");
    println!("cargo:rustc-link-lib=consv_bs_rainhash");

    // Set the LD_LIBRARY_PATH environment variable for the build process
    println!(
        "cargo:rustc-env=LD_LIBRARY_PATH=target/debug:../vole-rainhash-then-mayo-sys/target/debug"
    );

    // Generate bindings, but exclude the iteratively generated bindings
    // for openssl and the system functions
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg("-v")
        .clang_arg("-I../MAYO-C/include")
        .clang_arg("-I../MAYO-C/src")
        .clang_arg("-I../MAYO-C/src/common")
        .clang_arg("-I../MAYO-C/src/generic")
        .clang_arg("-I../MAYO-C/src/AVX2")
        .clang_arg("-I../MAYO-C/src/neon")
        .clang_arg("-I../mayo-c-sys")
        .clang_arg("-DENABLE_PARAMS_DYNAMIC=ON")
        .clang_arg("-DMAYO_BUILD_TYPE_REF")
        .generate_inline_functions(true)
        .wrap_static_fns(true)
        .generate()
        .expect("Unable to generate bindings");

    // Write bindings to file
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
