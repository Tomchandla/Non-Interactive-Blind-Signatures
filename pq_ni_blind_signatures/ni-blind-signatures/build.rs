fn main() {
    println!("cargo:rustc-link-search=../mayo-c-rain-sys/target/debug");
    println!("cargo:rustc-link-search=../vole-rainhash-then-mayo-sys/target/debug");

    println!("cargo:rustc-link-lib=mayo");
    println!("cargo:rustc-link-lib=consv_bs_rainhash");

    println!(
        "cargo:rustc-env=DYLD_LIBRARY_PATH=../mayo-c-rain-sys/target/debug:../vole-rainhash-then-mayo-sys/target/debug"
    );

    println!(
        "cargo:rustc-env=LD_LIBRARY_PATH=../mayo-c-rain-sys/target/debug:../vole-rainhash-then-mayo-sys/target/debug"
    );
}
