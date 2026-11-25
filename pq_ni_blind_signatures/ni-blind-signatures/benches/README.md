# Benchmarks

```bash
export RUST_MIN_STACK=8388608
cargo bench --bench nibs
```

This times KeyGen_S, KeyGen_R, Issue, Obtain (prove) and Verify for every selected instance, as the mean over `NIBS_BENCH_ITERS` runs (default 50) after 3 warm-up rounds. It writes:

* one box per instance to stdout and to `bench_results/<framework>_<zk>.txt`;
* `bench_results/summary.md` and `summary.csv`, with one row per instance (timings, presignature and signature size, witness bits, constraints).

Optional environment variables:

| Variable | Effect |
|---|---|
| `NIBS_BENCH_ITERS=20` | timed runs per phase |
| `NIBS_BENCH_ZK=SV1_128,FV2_256` | restrict the VOLEitH parameter sets (default: all 12) |
| `NIBS_BENCH_VARIANTS=BCGY,sPRP` | restrict the frameworks (default: both) |
| `NIBS_BENCH_CRITERION=1` | also run Criterion on Obtain and Verify (reports in `target/criterion/`) |

A full run over all 24 instances takes a few minutes at `NIBS_BENCH_ITERS=10` on one core, and proportionally longer at the default of 50. Most of that time goes to the level-5 "s" sets.

## Flamegraphs

```bash
cargo install flamegraph
export LD_LIBRARY_PATH=../mayo-c-rain-sys/target/debug:../vole-rainhash-then-mayo-sys/target/debug:$LD_LIBRARY_PATH
NIBS_BENCH_ZK=SV1_128 NIBS_BENCH_VARIANTS=BCGY NIBS_BENCH_ITERS=5 cargo flamegraph --bench nibs --freq 1000 --output flamegraph.svg
```

`perf` must be installed. On WSL, build it from the kernel sources (`tools/perf`).
