# mayo-c-sys

Rust bindings for the library [MAYO-C](https://github.com/PQCMayo/MAYO-C)

## Usage

These bindings are _not_ published on crates.io. Therefore, they have to be included manually in the `Cargo.toml` of the intended project, e.g.,

```toml
[dependencies]
mayo-c-sys = { path = "../mayo-c-sys" }
```

As MAYO-C can only be downloaded through their GitHub, the linkage to the library and the compilation have to be done manually. The build file [`build.rs`](build.rs) of `mayo-c-sys` first calls the makefile that compiles MAYO, and then generates shared library files in the target folder. In the build file, the shared library file is linked, and the bindings are generated.

Since MAYO is not installed system-wide with this method, the libraries have to be linked manually in the `build.rs` file of the new library. This could look like this:

```rust
fn main() {
    // Specify the library search paths
    println!("cargo:rustc-link-search=../mayo-c-sys/target/debug");

    // Specify the libraries to link
    println!("cargo:rustc-link-lib=mayo");

    // Set the LD_LIBRARY_PATH environment variable for the build process
    println!("cargo:rustc-env=DYLD_LIBRARY_PATH=../mayo-c-sys/target/debug");

    // Set the DYLD_LIBRARY_PATH to make the linking work on macOS
    println!("cargo:rustc-env=LD_LIBRARY_PATH=../mayo-c-sys/target/debug");
}
```

Then, the included library should be usable in the new project.

## The Makefile

As mentioned before, the other library has to be compiled, which we split into separate steps. The other libraries are included in this project as submodules, which means that they have to be manually initialized as submodules. Thereafter, they are compiled using the respective makefiles and then converted to shared libraries.

## Requirements

An `openssl` installation is required in order to compile MAYO.

## Limitations

The bindings here are only used in a closed environment. More general bindings would be nice, but are sufficient for our use case here.
Rusts allocation of stacksizes for the main file is adaptive, but for tests, a small stacksize limits the amount of allocatable stack.
However, for larger parameters of MAYO-C, this bound is easily exceeded in the execution. Therefore, in order to run tests, you have to manually adjust the stack size of test before executing them.
There are two options for this:

```bash
RUST_MIN_STACK=4194304 cargo test # sets the stacksize to 4MB for one test execution
# or
export RUST_MIN_STACK=4194304 # sets the stacksize to 4MB within that shell
cargo test # now uses the modified stacksize
```
