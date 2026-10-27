# LowMC implementation

LowMC instances for NIST levels 1, 3 and 5, used as the (strong) pseudorandom permutation underlying the non-interactive blind-signature construction. Instance generation is deterministic: the public matrices are regenerated from a fixed PRG so any verifier can reconstruct them from the parameter tuple alone. The keyed permutation is deterministic in the ordinary sense that every block cipher is — the pseudorandomness is over the choice of key. This directory contains the cleartext cipher only: it produces the ciphertext, the per-round witness states, and the public matrices that the VOLE-in-the-Head circuit consumes. It contains no proving or verification logic so that the circuit can be validated against an independent evaluation of the same cipher.

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

LowMC is the keyed permutation P_K of the NIBS constructions (n = k = λ):

| Variant | Use of LowMC |
| --- | --- |
| BCGY | message m = LowMC_K(r); pk_R is a RainHash commitment to K |
| sPRP | pk_R = LowMC_K(0‖s) and m = LowMC_K(1‖r) (Algorithm 1), with the domain bit in bit λ−1 |

The VOLEitH prover shows in zero knowledge that it knows a K consistent with the public m (and, inside the witness, with pk_R and the presignature). LowMC is used instead of AES because of its AND count: a full encryption costs 3·m·r ANDs, and in VOLE-in-the-Head only the nonlinear part costs proof size. The gadget commits only the r post-S-box states (r·λ bits).

### Instances

| Level | n = k | S-boxes | identity bits | rounds | data complexity |
| --- | --- | --- | --- | --- | --- |
| 1 | 128 | 42 | 2 | 13 | 2^64 |
| 3 | 192 | 64 | 0 | 13 | 2^64 |
| 5 | 256 | 85 | 1 | 13 | 2^64 |

The round counts are the output of `determine_rounds.py` from the reference repository. All three instances are compiled in, and callers select one by NIST level.

### sPRP and binding

`encrypt` and `decrypt` are both implemented, so the forward and inverse oracles of the sPRP definition exist. `tests/sprp.rs` checks that E and D are mutually inverse at every level. The LowMC security claim is the standard single-key block-cipher claim, which is the (strong) PRP game, within the stated data complexity. The claim excludes related-key, known-key and chosen-key settings.

The implemented derivations follow the paper's Algorithm 1: pk_R = P_K(0‖s) and m = P_K(1‖r), with s, r ∈ {0,1}^{λ−1} and the domain bit in bit λ−1 of the block. Binding of pk_R to K is a chosen-key property, so the single-key LowMC claim doesn't cover it.

### File map

| File | Role |
| --- | --- |
| `lowmc_params.hpp` | The three instances (`nibs_lowmc::params<1/3/5>`) and derived sizes (`derived<LEVEL>`: identity bits, block and state bytes, AND count). Changing anything here changes the cipher. |
| `lowmc.hpp` | `Inst<LEVEL>` (C++), and the C ABI: `nibs_lowmc_init`, `nibs_lowmc_block_bytes`, `nibs_lowmc_rounds`, `nibs_lowmc_encrypt`, `nibs_lowmc_decrypt`, `nibs_lowmc_witness_states`, plus the matrix and round-constant accessors that the circuit uses. |
| `lowmc.cpp` | The implementation: Grain LFSR instance generation (freshly seeded per instance), encryption, decryption (inverse S-box and inverse linear layers), and witness recording. Derived from the reference implementation; see *Acknowledgements*. |

## Acknowledgements

The implementation in `pq_ni_blind_signatures/vole/conservative_bs/lowmc_plain` is based in part on the reference implementation of **LowMC**:
- https://github.com/LowMC/lowmc

This project uses substantial portions of the original implementation, particularly within `lowmc.cpp`, while modifying and extending the code where necessary to support the requirements of this project. Not all functionality from the original implementation is included.

Where code has been copied or adapted from the original implementation, the relevant source files include comments identifying the origin of the copied code. Project-specific modifications and deviations from the original implementation are also documented in those locations where appropriate.

The original LowMC implementation is distributed under the MIT License. Its copyright notice and license are retained in accordance with the terms of the MIT License.
