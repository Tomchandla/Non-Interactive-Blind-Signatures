# Manual installation

Step-by-step setup on a clean Ubuntu 24.04 install under WSL2. The build layout follows the reference implementation of [BBBMR26](https://github.com/shibammukherjee/pq_blind_signatures); versions in brackets are what we installed and tested against.

1. **Update the system**
   * `sudo apt update`
   * `sudo apt upgrade`

2. **Install git and clone**
   * `sudo apt install git`
   * `git clone --recurse-submodules <fill: your repository URL>`

   Cloning with submodules matters: MAYO-C is pulled in that way, and a missing
   submodule shows up later as a CMake error rather than a clear message.

3. **Install Rust** (rustc / cargo 1.96.1)
   * `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

4. **Install the remaining apt packages**
   * `sudo apt install build-essential`
   * `sudo apt install cmake` (3.28.3)
   * `sudo apt install libclang-dev` (LLVM 18.1.3)
   * `sudo apt install gnuplot` (6.0) — only needed for Criterion plots

5. **Install meson and ninja through pipx**

   The apt packages are too old for this build.
   * `sudo apt install pipx` (1.4.3)
   * `pipx ensurepath`
   * `pipx install meson` (1.11.1)
   * `pipx install ninja` (1.13.0)

6. **Select GCC 14**

   The proof system compiles as C23/C++23, which GCC 13 — the default on 24.04 —
   does not support. Install the newer compiler and make it the default:
   * `sudo apt install gcc-14 g++-14`
   * `sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 110`
   * `sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 110`

   We tested against 14.3.0. Changing the system default compiler can affect
   unrelated builds on the same machine.

7. **Raise the Rust stack limit**

   MAYO's map evaluation overflows the default thread stack:
   * `export RUST_MIN_STACK=8388608`

8. **Build and benchmark**
   * `<fill: build + bench commands>`
   * `<fill: expected runtime>`

9. **Read the results**

   Benchmark output is written to `<fill: log file>`.
