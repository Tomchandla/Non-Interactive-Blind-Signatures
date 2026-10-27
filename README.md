# Towards Practical Post-Quantum Non-Interactive Blind Signatures from VOLE-in-the-Head

## Overview

This project instantiates the generic non-interactive blind signature (NIBS) framework of Baldimtsi, Cheng, Goyal and Yadav ([BCGY24](https://eprint.iacr.org/2024/037)) — itself a strengthening of the notion introduced by Hanzlik ([Han23](https://eprint.iacr.org/2023/077)) — with post-quantum primitives: **MAYO** as the digital signature scheme, **VOLE-in-the-Head** (FAEST) as the NIZKPoK, **LowMC** as the PRF, and a **RainHash**-based commitment. A second framework replaces the PRF and the commitment with a single strong pseudorandom permutation, also instantiated with LowMC. The implementation extends the interactive blind signature of Baum, Beckmann, Beullens, Mukherjee and Rechberger ([BBBMR26](https://eprint.iacr.org/2026/109.pdf)), which combines the same MAYO/FAEST pairing in the interactive setting.

**Motivation.** Only one prior post-quantum NIBS satisfies the strong blindness notions of [BCGY24]: the lattice construction of Baldimtsi, Goyal and Yadav ([BGY24](https://eprint.iacr.org/2025/1771.pdf)), whose single (unbatched) signature is conservatively estimated at 306–308 KB. This work asks whether a multivariate + VOLEitH instantiation closes the gap between the theoretical framework and a deployable scheme.

## Contributions

1. **An efficient post-quantum NIBS instantiation.** Signatures of **20.66 KB** (BCGY framework) and **14.62 KB** (sPRP framework) at `SV1_128`, a 14–21× reduction over the state-of-the-art lattice NIBS, under UOV/WMQ and LowMC assumptions rather than lattice assumptions.
2. **A simplified generic framework.** The framework of [BCGY24] requires a signature scheme, a NIZKPoK, a PRF *and* a commitment scheme. We show the PRF and the commitment can be collapsed into a single **strong pseudorandom permutation** (sPRP), with proof sketches for one-more unforgeability, strong receiver blindness and strong nonce blindness.

Both frameworks are implemented at NIST levels 1, 3 and 5:

| Framework | Receiver key pk_R | Message m | Presignature |
|---|---|---|---|
| BCGY | ⌊RH(op ‖ K ‖ fill)⌋_2λ | LowMC_K(r) | salted MAYO on M = r ‖ pk_R |
| sPRP | LowMC_K(0 ‖ s) | LowMC_K(1 ‖ r) | salted MAYO on M = r ‖ pk_R |

## Project Structure

```
Non-Interactive-Blind-Signatures/
└── pq_ni_blind_signatures/
    ├── ni-blind-signatures/                  # NIBS protocol layer (Rust)
    │   ├── src/                              # KeyGenS/R, Issue, Obtain, Verify
    │   ├── tests/                            # round trips, sPRP, circuit soundness
    │   ├── benches/                          # timing harness
    │   └── bench_results/                    # benchmark output
    ├── mayo-c-rain-sys/                      # FFI to MAYO with the Rain target
    ├── vole-rainhash-then-mayo-sys/          # FFI to the VOLEitH circuit
    ├── vole/                                 # C++ VOLEitH proof system (FAEST)
    │   ├── faest-cpp-tmp/                    # shared build folder
    │   ├── conservative_bs/                  # circuit definitions
    │   │   ├── owf_proof.inc                 # the NIBS relation
    │   │   ├── nibs_layout.hpp               # witness layout and sizes
    │   │   └── lowmc_plain/                  # LowMC instances
    │   └── build_consv_bs_rainhash.sh
    ├── MAYO-C/                               # git submodule (CMake)
    └── bench_rainhash_nibs.sh
```

The C and C++ components are built as shared libraries and reached from Rust through `bindgen`-generated foreign function interfaces; the protocol layer itself is Rust. All VOLEitH circuits share one build directory, so the crates cannot be built concurrently.

## Requirements and Installation

Developed and tested on Ubuntu 24.04.4 LTS under WSL2 (kernel 6.18.33.2). The versions below are what our build was verified against, not established minimums — older releases may well work, but we have not tested them.

| Tool | Tested version | Notes |
|---|---|---|
| GCC | 14.3.0 | See note below — the version in the 24.04 archive is too old |
| Rust (cargo/rustc) | 1.96.1 | Crates use edition 2024, so 1.85 is the effective floor |
| meson | 1.11.1 | Install with `pipx`; the apt package is older |
| ninja | 1.13.0 | Install with `pipx` |
| pipx | 1.4.3 | `sudo apt install pipx && pipx ensurepath` |
| libclang | 18.1.3 | Required by `bindgen` for the Rust FFI |
| cmake | 3.28.3 | Required to build the MAYO-C submodule (declares a 3.10 minimum) |
| gnuplot | 6.0 | Optional, for Criterion benchmark plots |
| Python | 3.12.3 | |

**GCC.** The meson project builds with `c_std=c23` and `cpp_std=c++23`, which needs GCC 14. Ubuntu 24.04 ships GCC 13.3, so a newer toolchain must be installed from a PPA (or built from source) before anything will compile.

**libclang.** If `bindgen` fails to locate libclang, or picks up an older LLVM installation, point it at the right one explicitly:

```
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
```

**Submodules.** MAYO-C is a git submodule and is built with CMake, so clone with `--recurse-submodules` (or run `git submodule update --init` afterwards). A missing submodule surfaces as a CMake error rather than an obvious "not initialised" message.

**Stack size.** The MAYO map evaluation overflows Rust's default thread stack. Export
`RUST_MIN_STACK=8388608` before running tests or benchmarks.

**Reproducibility.** The C/C++ components compile with `-march=native -mtune=native`, so the resulting binaries are specific to the build machine.

Running from a VS Code terminal is convenient, as it resolves the toolchain and environment variables automatically.

### Build

Instructions for setting up the build are below. If a build fails after changes to the circuit, note that rebuilding the C++ library alone does not propagate through the FFI: clean the FFI crate and the protocol crate as well before rebuilding. A step-by-step guide is in [`pq_ni_blind_signatures/manual-installation.md`](pq_ni_blind_signatures/manual-installation.md).

### Testing

To test or benchmark the implementation yourself:

```
cd pq_ni_blind_signatures/ni-blind-signatures/
export RUST_MIN_STACK=8388608
cargo test --release --test nibs --test sprp --test soundness
cargo bench --bench nibs
```

More information on testing can be found in [`pq_ni_blind_signatures/ni-blind-signatures/README.md`](pq_ni_blind_signatures/ni-blind-signatures/README.md).

## Credits

This implementation builds on the reference implementation accompanying [BBBMR26](https://github.com/shibammukherjee/pq_blind_signatures) by Baum, Beckmann, Beullens, Mukherjee and Rechberger. The build system, the VOLEitH/FAEST proof system, the MAYO integration and the RainHash construction are theirs; the NIBS protocol layer, the LowMC gadget and the modified target derivation are ours. Third-party components carry their own licences: FAEST (MIT, FAEST Team), MAYO-C (Apache-2.0), and gsl-lite (MIT, Martin Moene / Microsoft).
