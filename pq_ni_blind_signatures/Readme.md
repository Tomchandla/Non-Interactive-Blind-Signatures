THIS NEEDS TO BE REQRITTEN FOR NIBS

# NIBS FROM 

## Overview

## Project Structure
```

```


### Modifications of other Libraries

### ZK Proofs using the FAEST Framework

## Requirements and Installation

We have a separate small installation guide, where we ran our code on a fresh installation of Ubuntu 24.04 on WSL.
The file is [here](manual-installation.md).

## Minimal Working Example

## Build

### Did you get this Repository as a ZIP Folder?

This project is initialized with git submodules and designed to be compiled using git submodules.
Hence, when you get this project as a ZIP folder the build naturally fails.
Here is what you can do to fix it after you unzipped this repository:
1. Manually download the MAYO-C repository ```git clone git@github.com:PQCMayo/MAYO-C.git```
2. Comment out the ```update_submodules``` command in ```mayo-c-sys/Makefile``` (because it is not linked as a submodule anymore)
3. The build scripts in the ```vole``` folder do not have execution rights anymore, so they need to be allowed to be executed, using ```chmod +x build_consv_bs_keccak_deg16.sh```, ```chmod +x build_consv_bs_keccak.sh```, ```chmod +x build_consv_bs_rainhash.sh``` or ```chmod +x build_opti_bs.sh``` depending on the construction that you want to test. 
4. For the benchmark script also add ```chmod +x bench.sh``` in the main directory. Also note, the `bench.sh` script itself adds the above permissions if one runs it.
5. Simply run `bench.sh` to get the benchmark numbers in `bench_log.txt` (easiest option!). This may tke several minutes depending on the machine. View `bench_log_misc.txt` and the terminal for compile and bench progress. The benchmarks themselves also act as test-cases verifying the final blind signatures.

As mentioned in the next chapter, all constructions use the same buildfolder for the C++ library so sometimes it is required to clean the build repository using the ```clean.sh``` script which also needs to be made executable.
When we tried compiled it from a ZIP folder we found that we had to call ```cargo bench``` more than once when we compiled for the first time, because meson, with which we compile the C++ code blocked it on the first try, because the folder was already registered with the other construction that was build previously.

### Problems with Building or Running Tests?

As all the circuits share the same build file for the underlying circuit, there sometimes appear to be problems in the build process.
As a solution, you can change into the `vole` folder and run `./clean.sh` and then build the library manually first. This way, the folder is reset.
The FFIs build the shared library and make it accessible to Rust.
Therefore, changing something in the circuit and then only building in C++ *does not* propagate these changes to the Rust part.
The FFIs need to be cleaned too: change into the desired FFI folder and run `cargo clean`.
Once they are cleaned, go back to the desired rust construction, run `cargo clean`, and try building it again.

## Benchmarks

Easiest option:
Just run `bench.sh`, grab a coffee and relax! Bench results are output in `bench_log.txt`. The miscellanenous bench results are output in `bench_log_misc.txt`. `bench.sh` may need ```chmod +x``` permission on first run as discussed above. Depending on the machine the full benching may some minutes. View `bench_log_misc.txt` and the terminal for compile and bench progress. The benchmarks themselves also act as test-cases verifying the final blind signatures

### More detailed Benchmarks

The same build tips from the previous section apply.
The benchmarks utilize [criterion](https://bheisler.github.io/criterion.rs/book/cargo_criterion/cargo_criterion.html).
To run the benchmarks, run `cargo bench` and potentially limit the constructions to those desired to be benchmarked.

For each construction, there are a total of 4 benchmarks: (1) sign1, (2) sign2, (3) sign3, and (4) verify.
Each of these runs the benchmark for each of the parameter sets.
If you only want to run the benchmarks for a subset, you can comment out the variants that you do not want to benchmark.
The benchmarks are then saved to the `target/criterion` folder, where the report can be viewed as an HTML file.
