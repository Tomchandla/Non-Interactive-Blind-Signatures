# NIBS protocol layer

Rust implementation of the non-interactive blind signature: KeyGen_S, KeyGen_R, Issue, Obtain and Verify. It covers both frameworks, at NIST levels 1, 3 and 5, with all twelve VOLEitH parameter sets:

| Framework | pk_R | message m | presignature |
|---|---|---|---|
| `BCGY` | ⌊RH(op ‖ K ‖ fill)⌋_2λ | LowMC_K(r) | salted MAYO on M = r ‖ pk_R |
| `sPRP` | LowMC_K(0 ‖ s) | LowMC_K(1 ‖ r) | salted MAYO on M = r ‖ pk_R |

In the sPRP framework (Algorithm 1), s and r are drawn from {0,1}^(λ−1); the top bit of the λ-bit block is the domain bit.

```rust
use ni_blind_signatures::{Framework, Nibs, NibsParams, ZKType};

let bs = Nibs::setup(NibsParams::new(Framework::Sprp, ZKType::SV1_128));
let (pk, sk) = bs.keygen_signer();
let epk = bs.expand_pk(&pk);
let (pk_r, sk_r) = bs.keygen_recipient();
let (presig, nonce) = bs.issue(&sk, &pk_r);
let (m, sig) = bs.obtain(&pk, &epk, &sk_r, &presig, &nonce).expect("valid presignature");
assert!(bs.verify(&pk, &epk, &m, &sig));
```

Layout: `src/params.rs` (frameworks and parameter sets), `src/nibs/` (the five algorithms), `src/zk.rs` (the VOLEitH FFI). The witness layout and target-hash mode are documented in [`../vole/conservative_bs/nibs_layout.hpp`](../vole/conservative_bs/nibs_layout.hpp).

## Tests

The MAYO code needs a larger stack than Rust's default:

```bash
export RUST_MIN_STACK=8388608
cargo test --release --test nibs --test sprp --test soundness
NIBS_TEST_ALL=1 cargo test --release --test nibs          # round trip on all 24 instances
NIBS_SOUNDNESS_EXHAUSTIVE=1 cargo test --release --test soundness -- --ignored   # flip every witness bit (level 1, slow)
```

* `tests/nibs.rs` covers round trips, rejection of modified statements, proofs and presignatures, fresh VOLE randomness, size bookkeeping and the nonce-first message encoding.
* `tests/sprp.rs` covers LowMC as an invertible keyed permutation, the sPRP derivations, and the counterexample to the paper's Definition 4.4.
* `tests/soundness.rs` evaluates the circuit directly, without proofs: honest witnesses satisfy it, and wrong secrets or flipped witness bits do not.

## Sizes and benchmarks

```bash
cargo run --release --example sizes      # sizes, witness and constraint counts of every instance
cargo bench --bench nibs                 # timings; see benches/README.md
```
