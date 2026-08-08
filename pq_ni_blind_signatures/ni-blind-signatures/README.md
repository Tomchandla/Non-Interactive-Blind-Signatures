# NIBS implementation and benchmarks

## Tests

The default Rust stack is not large enough for some of the MAYO-C transformations, so the tests need to run with an increased stack size:

```bash
RUST_MIN_STACK=8388608 cargo test
```

To run only the integration tests, with output shown:

```bash
RUST_MIN_STACK=8388608 cargo test --test nibs_rain -- --nocapture
```

## Benchmarks

The benchmarks need the same enlarged stack as the tests:

```bash
RUST_MIN_STACK=8388608 cargo bench --bench ni_blind_sig_rain
```

Every run covers all four parameter sets — `FV1_128`, `FV2_128`, `SV1_128` and `SV2_128` — and times five phases in each: `keygen_signer`, `keygen_recipient`, `issue`, `obtain` and `verify`. LowMC setup is measured once and shared, since it is a one-time cost.

Two kinds of output are produced.

Criterion's own statistics, with confidence intervals and comparisons against the previous run, go to `target/criterion/`; the HTML report is at `target/criterion/report/index.html`. Filter to a subset by naming a group, for example `cargo bench nibs_lowmc/SV1_128`.

Alongside that, the benchmark writes a plain-text summary per parameter set to `bench_results/nibs_lowmc_<PARAM_SET>.txt` and prints it to stdout. Each summary gives mean timings over 50 runs, the presignature and signature sizes, the protocol object lengths, and the LowMC and Rain instances in use. These files are committed, so `git diff bench_results/` after a run shows whether anything has shifted.

`obtain` and `verify` each take on the order of 100 ms, so Criterion's default 5-second measurement window is not enough for a full sample. The budget for those two phases defaults to 30 seconds and can be raised for tighter intervals:

```bash
NIBS_BENCH_SECS=45 RUST_MIN_STACK=8388608 cargo bench --bench ni_blind_sig_rain
```

Expect a full run to take several minutes.
