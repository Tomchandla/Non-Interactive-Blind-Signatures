# Manual installation

In this small guide, we show the individual steps to download all required dependencies to run our codeon a completely fresh installation of Ubuntu 24.04 on WSL.

1. **Update the system**
* `sudo apt get update`
* `apt upgrade`

2. **Download git and clone the repository**
> **Note:** We do it here with the GitHub version, but our README also has a short explanation explaining the challenges that might arise when doing it with the zip folder.

* `sudo apt-get install git-all`
* `git clone https://github.com/shibammukherjee/pq_blind_signatures.git`

3. **Download Rust**
* `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` (rustc 1.93.0)

4. **Direct download of dependencies**
* `sudo apt install cmake` (cmake version 3.28.3)
* `sudo apt install libclang-dev`
* `sudo apt install gnuplot` (gnuplot 6.0 patchlevel 0)
* `sudo apt install build-essential`

5. **Manual installation of meson and ninja via pipx**
*Apt provides versions that are too old for these tools.*
* `sudo apt install pipx` (1.4.3)
* `pipx ensurepath`
* `pipx install meson` (1.10.1)
* `pipx install ninja` (1.13.0)

6. **Download and set gcc-14 and g++-14 as default**
*Manual download is required; note that changing default settings might cause issues in specific edge cases.*
* `sudo apt install gcc-14 g++-14` (gcc-14 14.2.0 and g++-14 14.2.0)
* `sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 110`
* `sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 110`

7. **Configure an SSH key**
Required to retrieve submodules (e.g., MAYO and XKCP) from GitHub. Alternatively, clone repositories manually and remove the lines of code where the submodules are instantiated.

8. **Reproduce our Results**
Now, you can run our code and for example reproduce our benchmarks by running 
* `./bench.sh` (took roughly 15 minutes to finish in our trial)

9. **View the Results**
You can view your own benchmarking results in `bench_log.txt`.