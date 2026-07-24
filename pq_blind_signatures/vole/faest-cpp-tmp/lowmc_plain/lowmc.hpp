// lowmc.hpp -- LowMC for the NIBS_MAYO_VOLE project.
//
// Faithful port of the reference implementation at
// https://github.com/LowMC/lowmc (LowMC.cpp / LowMC.h), with these
// deliberate deviations, each documented where it happens in lowmc.cpp:
//
//   1. blocksize is fixed at 256 (std::bitset<256>), but numofboxes,
//      keysize and rounds are runtime constructor parameters, so one
//      translation unit can host both NIBS instances.
//   2. Decryption and the inverse matrices are dropped (never needed;
//      computing them consumed no PRG bits in the reference, so the
//      instance constants are unaffected).
//   3. The self-shrinking-LFSR PRG (getrandbit) is process-global and
//      shared across instantiations, exactly as in the reference (where
//      it is a function-local static). Constants therefore depend on
//      instantiation ORDER, which nibs_lowmc_init() fixes permanently:
//      HASH instance (22 rounds) first, PRF instance (13 rounds) second.
//      Never construct instances in any other order.
//
// Instances (rounds from the reference repo's determine_rounds.py):
//
//   NIBS_LOWMC_HASH : n=256, k=256, m=85 boxes, r=22   (d = 2^256)
//     ./determine_rounds.py -q 256 85 256 256  ->  22
//     Used inside the MMO compression for Gad1 (com). (Gad2 -- MAYO's
//     message hash t -- is Rain, not LowMC, in the mixed circuit.)
//     Max-data instance: in hash mode the "key" input is adversarially
//     known/influenced, so we take the largest data-complexity margin
//     the round formula supports (residual ideal-cipher-style
//     assumption for MMO collision resistance; see INTEGRATION.md).
//
//   NIBS_LOWMC_PRF  : n=256, k=256, m=85 boxes, r=13   (d = 2^64)
//     ./determine_rounds.py -q 256 85 64 256   ->  13
//     Used keyed by skR for GadA (pkR) and GadM (m). The 2^64 data
//     bound caps issuances per recipient key; state this in the thesis.
//
// Bit/byte packing convention used EVERYWHERE (Rust, C, circuit):
//   bit i of a 256-bit block  <->  (bytes[i >> 3] >> (i & 7)) & 1
// i.e. LSB-first within each byte, byte 0 first. Matrix rows are
// exported bit-packed the same way, 32 bytes per row, row-major.

#ifndef NIBS_LOWMC_H
#define NIBS_LOWMC_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    NIBS_LOWMC_HASH = 0,   // 22 rounds -- MMO compression (Gad1)
    NIBS_LOWMC_PRF  = 1,   // 13 rounds -- keyed by skR  (GadA, GadM)
};

enum {
    NIBS_LOWMC_BLOCK_BYTES = 32,   // n = 256
    NIBS_LOWMC_KEY_BYTES   = 32,   // k = 256
    NIBS_LOWMC_BOXES       = 85,   // full S-box layer: 255 bits + 1 identity bit
    NIBS_LOWMC_HASH_ROUNDS = 22,
    NIBS_LOWMC_PRF_ROUNDS  = 13,
};

// One-time instantiation of both instances (idempotent, not thread-safe
// on first call). Must run before any other function here. Instantiation
// order is part of the spec -- see file header.
void nibs_lowmc_init(void);

unsigned nibs_lowmc_rounds(int inst);

// ct = E^inst_key(pt)
void nibs_lowmc_encrypt(int inst,
                        const uint8_t key[NIBS_LOWMC_KEY_BYTES],
                        const uint8_t pt[NIBS_LOWMC_BLOCK_BYTES],
                        uint8_t ct[NIBS_LOWMC_BLOCK_BYTES]);

// Matyas-Meyer-Oseas compression with the HASH instance:
//   out = E^HASH_chain(msg) XOR msg
void nibs_lowmc_mmo(const uint8_t chain[NIBS_LOWMC_KEY_BYTES],
                    const uint8_t msg[NIBS_LOWMC_BLOCK_BYTES],
                    uint8_t out[NIBS_LOWMC_BLOCK_BYTES]);

// Witness expansion for the FAEST prover: records the POST-S-BOX state
// of every round (32 B per round, rounds(inst) * 32 B total). These are
// exactly the bits the circuit gadget witnesses; everything else in the
// gadget is a linear function of them, the key wires and constants.
// Returns the ciphertext as well (may pass ct = NULL to discard).
void nibs_lowmc_witness_states(int inst,
                               const uint8_t key[NIBS_LOWMC_KEY_BYTES],
                               const uint8_t pt[NIBS_LOWMC_BLOCK_BYTES],
                               uint8_t* states /* rounds*32 bytes */,
                               uint8_t ct[NIBS_LOWMC_BLOCK_BYTES]);

// Constant accessors for the circuit (valid after nibs_lowmc_init()):
//   linmat(inst, r)   : r in [0, rounds)    -- 256 rows x 32 B, L_r
//   keymat(inst, r)   : r in [0, rounds]    -- 256 rows x 32 B, KM_r
//   roundconst(inst,r): r in [0, rounds)    -- 32 B, C_r
// Row i, bit-packed per the convention above: out_bit[i] = <row_i, in>.
const uint8_t* nibs_lowmc_linmat(int inst, unsigned r);
const uint8_t* nibs_lowmc_keymat(int inst, unsigned r);
const uint8_t* nibs_lowmc_roundconst(int inst, unsigned r);

// ---------------------------------------------------------------------------
// NIBS derivations (in-the-clear mirrors of the circuit gadgets).
// Domain separation lives in plaintext byte 0; open/nonce occupy bytes 1..16.
// Byte 0 differing across the two skR-keyed calls makes m = pkR impossible
// even for adversarially chosen nonces (the pitfall flagged in derive.rs).
//
// The MAYO target t is NOT derived here anymore: t = Rain(com | salt | cap)
// is computed by the MAYO signer (mayo-c-rain-sys, sign_fixed_length_rain)
// and proven by the Rain gadget 2 -- see parameters_lowmc.hpp.
// ---------------------------------------------------------------------------
enum {
    NIBS_DOM_PK  = 0x01,   // GadA : pkR = E^PRF_skR( PT(DOM_PK, open) )
    NIBS_DOM_M   = 0x02,   // GadM : m   = E^PRF_skR( PT(DOM_M, nonce) )
    NIBS_DOM_COM = 0x03,   // Gad1 : com = MMO(pkR, PT(DOM_COM, nonce))
    NIBS_LOWMC_OPEN_BYTES  = 16,   // (namespaced faest::NIBS_OPEN_BYTES is
    NIBS_LOWMC_NONCE_BYTES = 16,   //  the canonical constant on the C++ side)
};

// Builds PT = [dom, payload(16 B), 0x00 x 15]. payload may be NULL (zeros).
void nibs_lowmc_build_pt(uint8_t dom, const uint8_t* payload16,
                         uint8_t pt[NIBS_LOWMC_BLOCK_BYTES]);

// pkR = Com(skR; open) = E^PRF_skR( PT(DOM_PK, open) ). The opening
// randomness makes the receiver key a bona-fide commitment to skR in the
// sense of BCGY24's generic construction (skR alone would be a bare keyed
// evaluation; open restores the Com(K; s) shape and its hiding argument).
void nibs_derive_pkr(const uint8_t skR[32], const uint8_t open[16],
                     uint8_t pkR[32]);
void nibs_derive_com(const uint8_t pkR[32], const uint8_t nonce[16],
                     uint8_t com[32]);
void nibs_derive_message(const uint8_t skR[32], const uint8_t nonce[16],
                         uint8_t m[32]);

// Witness expansion for the three LowMC gadgets, laid out exactly as
// parameters_lowmc.hpp expects (see NIBS_* offsets there):
//   skR(32) || open(16) || nonce(16) || A states(13*32)
//   || 1 states(22*32) || M states(13*32)                     = 1600 B
// The Rain gadget-2 region (com | salt | cap in-block, 7 Rain state blocks,
// out-block) is appended by get_witness_nibs in faest.inc, which needs com
// to build the Rain in-block -- hence the com_out parameter. The MAYO
// preimage s is appended after that by the existing MAYO witness packing.
enum { NIBS_LOWMC_WITNESS_BYTES = 32 + 16 + 16 + (13 + 22 + 13) * 32 };
void nibs_lowmc_witness_expand(const uint8_t skR[32],
                               const uint8_t open[16],
                               const uint8_t nonce[16],
                               uint8_t out[NIBS_LOWMC_WITNESS_BYTES],
                               uint8_t com_out[32]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NIBS_LOWMC_H
