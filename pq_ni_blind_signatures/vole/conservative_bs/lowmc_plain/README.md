# LowMC implmentation

A deterministic, single-instance LowMC used as the strong pseudorandom permutation underlying the non-interactive blind-signature construction. Deterministic here refers to instance generation: the public matrices are regenerated from a fixed PRG so any verifier can reconstruct them from the parameter tuple alone. The keyed permutation is deterministic in the ordinary sense that every block cipher is — the pseudorandomness is over the choice of key. This directory contains the cleartext cipher only: it produces the ciphertext, the per-round witness states, and the public matrices that the VOLE-in-the-Head circuit consumes. It contains no proving or verification logic so that the circuit can be validated against an independent evaluation of the same cipher.

---

## How LowMC works

LowMC is a family of block ciphers designed to minimise **multiplicative complexity** — the number of AND gates needed to evaluate it. That target comes from its intended settings: in MPC, FHE, and zero-knowledge proof systems, XOR operations are close to free, while every AND costs communication, noise growth, or proof size.

A LowMC instance is fixed by four parameters:

| Symbol | Meaning |
| --- | --- |
| `n` | block size in bits |
| `k` | key size in bits |
| `m` | number of S-boxes per round |
| `r` | number of rounds |

It is a substitution–permutation network (SPN) with two refinements.

**Partial S-box layer.** Each round applies `m` parallel 3-bit S-boxes to the low `3m` bits of the state; the remaining `n - 3m` bits pass through the identity. The S-box is a degree-2 permutation on F2^3 costing **3 AND gates at AND-depth 1**, so a round costs `3m` ANDs regardless of block size, and a full encryption costs exactly `3mr`.

**Pseudorandom affine layers.** LowMC uses independently sampled invertible `n × n` matrices over F2 — one per round — plus a random round constant, and derives round keys by multiplying the master key by a sampled `n × k` matrix. Nothing is free-form here in the security argument: the matrices are *public* and *fixed per instance*, and the design assumes only that they behave like uniform random invertible maps.

The round function, for `i = 1..r`:

```
state ← Sbox_layer(state)          # 3m ANDs, depth 1
state ← L_i · state                # F2-linear, free
state ← state ⊕ C_i                # affine, free
state ← state ⊕ (M_i · key)        # round key, free
```

preceded by a whitening key addition `state ← plaintext ⊕ (M_0 · key)`. Because everything except the S-box layer is F2-affine, all of the cost in a proof system concentrates in `3mr`. Tuning `m` down and `r` up (or the reverse) lets you trade AND-depth against total AND count without changing the security target — this flexibility is the main reason LowMC is attractive here.

The security cost of the design is that the low algebraic degree that makes it cheap also makes it a target.

### Further reading

- **Interactive walkthrough:** <https://asecuritysite.com/pqc/lowmc> — a hands-on overview with worked examples, useful for building intuition before reading the specification.
- **Specification:** Albrecht, Rechberger, Schneider, Tiessen, Zohner, *Ciphers for MPC and FHE*, Cryptology ePrint Archive, Report 2016/687 — <https://eprint.iacr.org/2016/687>. This is the ePrint version, which carries the revised round formula and security analysis (LowMC v2) rather than the original conference text; cite this one.
- **Reference implementation:** <https://github.com/LowMC/lowmc>.

---

## How LowMC is used within NIBS

### Role in the scheme

LowMC is the strong pseudorandom permutation underlying the signature relation. The signer holds a key `K`; given a nonce `r`, the message is defined as `m = E_K(r)`, and the prover shows in zero knowledge that it knows a `K` consistent with the public `(r, m)` pair. The choice of LowMC over, say, AES is the AND count: under VOLE-in-the-Head the proof size scales with the number of AND gates, XOR gates are free for the same reason they are free under free-XOR, and a full encryption is exactly `3mr` ANDs.

### File map

| File | Role |
| --- | --- |
| `../params_lowmc.hpp` | Scheme-level parameters. Selects the security level and defines the derived byte-length macros (`NIBS_LOWMC_KEY_BYTES`, `NIBS_LOWMC_NONCE_BYTES`, `NIBS_LOWMC_STATE_BYTES`, `NIBS_LOWMC_WITNESS_BYTES`) that fix the witness layout. |
| `lowmc_parms.hpp` | The cipher instance itself: `NIBS_LOWMC_BLOCK_BITS`, `NIBS_LOWMC_KEY_BITS`, `NIBS_LOWMC_BOXES`, `NIBS_LOWMC_ROUNDS`, `NIBS_LOWMC_LEVEL`. Changing anything here changes the cipher; see *Determinism* below. |
| `lowmc.hpp` | The C-ABI surface. Declares the `extern "C"` entry points so the prover and the circuit builder can link against this without pulling in C++ template machinery. |
| `lowmc.cpp` | The implementation: PRG, instance generation, encryption, witness recording, and the flattened matrix exports. Derived from the reference implementation; see `Acknowledgements`. |

---

## Acknowledgements

The implementation in `pq_blind_signatures/vole/conservative_bs/lowmc_plain` is based in part on the reference implementation of **LowMC**:
- https://github.com/LowMC/lowmc

This project uses substantial portions of the original implementation, particularly within `lowmc.cpp`, while modifying and extending the code where necessary to support the requirements of this project. Not all functionality from the original implementation is included.

Where code has been copied or adapted from the original implementation, the relevant source files include comments identifying the origin of the copied code. Project-specific modifications and deviations from the original implementation are also documented in those locations where appropriate.

The original LowMC implementation is distributed under the MIT License. Its copyright notice and license are retained in accordance with the terms of the MIT License.
