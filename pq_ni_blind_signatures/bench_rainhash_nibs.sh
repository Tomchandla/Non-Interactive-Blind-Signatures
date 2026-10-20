#!/bin/bash
# Build everything and benchmark the NIBS variants.
#
#   ./bench_rainhash_nibs.sh                 # all 4 variants x 12 VOLEitH sets
#   NIBS_BENCH_ZK=SV1_128,SV1_192,SV1_256 ./bench_rainhash_nibs.sh
#   NIBS_BENCH_VARIANTS=BCGY+MAYO,sPRP+OMM NIBS_BENCH_ITERS=20 ./bench_rainhash_nibs.sh
#
# Results: ni-blind-signatures/bench_results/{summary.md,summary.csv,<variant>_<set>.txt}
set -euo pipefail
cd "$(dirname "$0")"

export RUST_MIN_STACK=${RUST_MIN_STACK:-8388608}
if [ -z "${LIBCLANG_PATH:-}" ] && [ -d /usr/lib/llvm-18/lib ]; then
    export LIBCLANG_PATH=/usr/lib/llvm-18/lib
fi

cd ni-blind-signatures
cargo test --release --test nibs --test sprp --test soundness
cargo bench --bench nibs
echo
echo "summary: $(pwd)/bench_results/summary.md"
