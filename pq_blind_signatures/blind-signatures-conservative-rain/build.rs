fn main() {
    // Specify the library search paths
    println!("cargo:rustc-link-search=../mayo-c-rain-sys/target/debug");
    println!("cargo:rustc-link-search=../vole-rainhash-then-mayo-sys/target/debug");

    // Specify the libraries to link
    println!("cargo:rustc-link-lib=mayo");
    println!("cargo:rustc-link-lib=consv_bs_rainhash");

    // Set the LD_LIBRARY_PATH environment variable for the build process
    println!(
        "cargo:rustc-env=DYLD_LIBRARY_PATH=../mayo-c-rain-sys/target/debug:../vole-rainhash-then-mayo-sys/target/debug"
    );

    // Set the DYLD_LIBRARY_PATH to make the linking work on macOS
    println!(
        "cargo:rustc-env=LD_LIBRARY_PATH=../mayo-c-rain-sys/target/debug:../vole-rainhash-then-mayo-sys/target/debug"
    );
}
