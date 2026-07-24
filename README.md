# Non-interactive blind signatures from MAYO, LowMC and Rain over VOLEitH

This project converts the interactive blind signature of ([BBBMR26](https://eprint.iacr.org/2026/109.pdf)) into a non-interactive blind signature (NIBS) in the model introduced by Hanzlik ([Han23](https://eprint.iacr.org/2023/077)) and improved upon by Baldimtsi et al. ([BCGY24](https://eprint.iacr.org/2024/037)). It takes the *conservative RainHash* variant of [BBBMR26] as its starting template and aligns it to the generic NIBS construction of [BCGY24] (PRF + commitment + signature + NIZK), instantiated with a **mixed LowMC/Rain circuit**: LowMC as the PRF and commitment, Rain as the message hash internal to MAYO.

**Research question.** NIBS has been realised from lattices — most recently the batched construction of Baldimtsi, Goyal and Yadav ([BGY25](https://eprint.iacr.org/2025/1771.pdf)), secure under randomised one-more-ISIS and standard lattice assumptions in the ROM. This project asks whether a **multivariate + VOLEitH** instantiation gives a competitive or better NIBS, and if so whether the same composition transfers to related primitives such as group signatures.

---

## Construction

Notation: `PT(δ, x) = δ ‖ x ‖ 0*` is a 256-bit plaintext block with domain byte δ (`δ_pk = 0x01`, `δ_m = 0x02`, `δ_com = 0x03`). `E_prf` is 13-round LowMC (n = k = 256, m = 85, d = 2^64); `E_h` is the 22-round instance (d = 2^256). `MMO(c, x) = E_h_c(x) ⊕ x`. Rain is the 512-bit, 7-round instance.

### NIBS from lattice assumptions ([BGY25], for comparison)

```
Setup   : <fill>
KeyGenS : <fill>
KeyGenR : <fill>
Issue   : <fill>
Obtain  : <fill>
Verify  : <fill>
```

### NIBS from MAYO + LowMC + Rain (this work)

```
Setup   : pp = MAYO public params + LowMC/Rain instances + FAEST params
KeyGenS : (pkS, skS) ← MAYO.KeyGen                        // signer, unchanged
KeyGenR : K ←$ {0,1}^256 ; s ←$ {0,1}^128
          pkR = E_prf_K(PT(δ_pk, s)) ; skR = (K, s)
Issue   : nonce ←$ {0,1}^128
          presig = MAYO.Sign^H(skS, pkR ‖ nonce)
          // MAYO's message hash H, composed:
          //   com = MMO(pkR, PT(δ_com, nonce))            (LowMC)
          //   t   = Rain(com ‖ salt ‖ 0xff^8)             (Rain)
          // then sample s_M with P*(s_M) = t
Obtain  : recompute pkR ; check presig against pkR ‖ nonce
          m = E_prf_K(PT(δ_m, nonce))
          π = VOLEitH proof of the circuit below ; output (m, π)
Verify  : FAEST verify with public (pkS, m)
```

There is no recipient→signer message: the signer derives the MAYO target itself from `(pkR, nonce)` — the MMO step is part of the composed message hash, not a protocol-level commitment — and the recipient finalises the presignature locally. Presignatures and nonces are precomputable offline and may be published.

### Verification circuit (mixed LowMC/Rain)

```
GadA  : pkR = E_prf_K(PT(δ_pk, s))                LowMC 13r    witness: K, s
Gad1  : com = MMO(pkR, PT(δ_com, nonce))          LowMC 22r    witness: nonce
Gad2  : t   = Rain(com ‖ salt ‖ 0xff^8)           Rain 7r      witness: salt   (unchanged)
MAYO  : P*(s_M) = t                                            witness: s_M    (unchanged)
GadM  : m   = E_prf_K(PT(δ_m, nonce))             LowMC 13r    output == public m
```

`pkR`, `com` and `t` are intermediate values, never public — the verifier learns only `(pkS, m)`, which is what unlinkability requires.

**Gadget split.** The primitive is selected per gadget by two questions — is it keyed by a secret the adversary cannot query, and is its input adversarially controllable?
- `GadA`/`GadM` are keyed by `K`, which the adversary never sees: PRF strength at d = 2^64 suffices (13 rounds).
- `Gad1` compresses under the *public* `pkR` with adversarially-influenced input, so it needs collision resistance: 22 rounds under MMO.
- `Gad2` also needs collision resistance, but its input is already compressed — Rain wins decisively there (4 constraints/round vs 255).

**Binding.** Most inter-gadget binding is structural and free: `K` is one set of witness wires consumed by both `GadA` and `GadM`; `nonce` by `Gad1` and `GadM`. One seam is **not** free: the LowMC gadgets emit `com` as a linear expression over committed bits, while the Rain loader consumes lane-combined field elements, so binding `Gad2`'s input to `Gad1`'s output costs **256 explicit F₂ equality constraints**, and the public output `m` costs another 256. These 512 constraints are the measured price of the primitive split.

**Domain separation.** The bytes `δ_pk`, `δ_m`, `δ_com` keep the LowMC uses disjoint. Without them the signer — who knows `pkR` and `nonce` — could relate `m` to issuance-time values and blindness would fail; `m` depending on `K` (which the signer never sees) is what makes it unlinkable.

**Salt gotcha.** MAYO1's salt is 24 bytes, so it straddles the 128-bit lane boundary of the Rain input block (lane 2 + half of lane 3); both lanes must be witness-loaded. Treating lane 3 as constant pad silently truncates the salt in-circuit and is invisible to honest-execution testing. Revisit at L3/L5 (32- and 40-byte salts).

---

## Sizes (L1, mixed layout)

```
K + s + nonce                        512 bits
GadA post-S-box states  (13 × 256)  3328
Gad1 post-S-box states  (22 × 256)  5632
GadM post-S-box states  (13 × 256)  3328
Gad2 input block                     512
Gad2 Rain states         (7 × 512)  3584
Gad2 output block                    512
                                   -----
WITNESS_SIZE_BITS                  17408 bits = 2176 B   (+ MAYO preimage s_M at offset 17408)
```

12,833 constraints total: 256 per LowMC round (255 quadratic S-box + 1 linear), 4 inversion + 4 output-consistency per Rain round, plus the 512 seam/output equalities.

## Measured results (preliminary — correctness verification in progress)

| | FV1_128 | FV2_128 | SV1_128 | SV2_128 |
|---|---|---|---|---|
| τ | 16 | 16 | 9 | 11 |
| \|σ\| (KB) | 43.78 | 43.75 | **25.52** | 30.50 |
| \|presig\| (KB) | 0.443 | 0.443 | 0.443 | 0.443 |
| Obtain / Verify (ms) | 54 / 52 | 56 / 53 | 122 / 127 | 62 / 57 |

Signer→recipient communication is 0.459 KB (presig + nonce), ~14–20% below [BGY25]'s 0.68 KB. LowMC instance generation is a one-time 237 ms cost.

**Vs the interactive scheme [BBBMR26]** (16.5 / 27.8 KB s/f): 1.55× / 1.58× larger. The gap has a closed form — the witness enters the proof once per repetition, so Δ|σ| = τ · Δw = τ · 1024 B: the interactive protocol proves a two-gadget 9216-bit circuit, while removing the round trip forces `GadA`, `Gad1`, `GadM` and their key material in-circuit (the 12800-bit LowMC region in place of one 4608-bit Rain gadget). The cost of non-interactivity is structural, not an implementation artefact.

**Vs lattice NIBS [BGY25]** (306 KB unbatched, conservative): ~12× smaller at SV1, ~7× at FV1 — under multivariate (UOV/WMQ) + LowMC assumptions rather than lattices. BGY25's efficiency story is *amortized* batching, out of scope here, so this compares single-shot sizes only.

## Open optimisations

1. Eliminate in-circuit verification of MAYO's message hash by binding the target through a one-time pad, adapting [BBBMR26]'s technique — the non-interactive obstacle is that there is no recipient→signer message in which to commit to the pad, so it must be bound through the recipient's published key material.
2. Commit less LowMC round state: the current layout commits every post-S-box state in full, but the 255-of-256 bits per round through the S-box layer are not all independently required.
