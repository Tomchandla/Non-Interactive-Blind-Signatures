# Docker Instructions -
# 1# Build
# sudo docker build -t pq_blind_signatures . 

# 2# Run and Bench
# sudo docker run -it --rm pq_blind_signatures:latest /bin/bash
# cd pq_blind_signatures

# ./bench_conservative_bs.sh
# ./bench_conservative_deg16_bs.sh
# ./bench_optimized_bs.sh
# ./bench_rainhash_bs.sh
# ./bench_all_bs.sh

# (optional 3# to copy results to host or just use some text editor in docker)
# 3# In a separate terminal
# sudo docker ps (get the container ID, something like e08112f17205)
# docker cp e08112f17205:pq_blind_signatures/bench_log.txt ./bench_log.txt



FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

ENV PATH="/root/.local/bin:${PATH}"

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    cmake \
    g++ \
    wget \
    make \
    git \
    libclang-dev \
    gnuplot \
    pipx \
    && rm -rf /var/lib/apt/lists/*


RUN git clone https://github.com/shibammukherjee/pq_blind_signatures.git

RUN curl -proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustc --version && cargo --version

RUN pipx ensurepath --force && pipx install ninja meson && ninja --version && meson --version

RUN cd pq_blind_signatures && ls -l



