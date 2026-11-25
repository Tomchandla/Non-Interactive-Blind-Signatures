#ifndef FAEST_H
#define FAEST_H

// C interface of the NIBS VOLEitH library (libconsv_bs_rainhash).
//
// An instance is selected by
//   variant : NIBS_VARIANT_*            (BCGY or sPRP framework)
//   level   : 1, 3 or 5                 (NIST level; lambda = 128/192/256)
//   speed   : 0 = "s" (small), 1 = "f" (fast)
//   version : 1 or 2                    (FAEST v1 / v2 VOLEitH parameters)
//
// All byte strings use the sizes reported by nibs_instance_info_get.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum
{
    // BCGY24 framework: pk_R = Rain(op || K)[0 : 2 lambda], m = LowMC_K(r);
    // MAYO with salt on M = r || pk_R.
    NIBS_VARIANT_BCGY = 0,
    // sPRP framework (Algorithm 1): sk_R = (K, s), pk_R = LowMC_K(0||s),
    // m = LowMC_K(1||r); MAYO with salt on M = r || pk_R. s is passed in the
    // op argument.
    NIBS_VARIANT_SPRP = 1,
};

typedef struct
{
    size_t proof_bytes;       // |sigma|
    size_t random_seed_bytes; // fresh randomness the prover needs (lambda/8)
    size_t witness_bits;      // VOLEitH witness: NIBS part + MAYO preimage
    size_t nibs_witness_bits; // NIBS part only
    size_t mayo_s_bits;       // MAYO preimage part
    size_t constraints;       // QuickSilver constraints
    size_t tau;               // VOLEitH repetition parameter
    size_t k_bytes;           // receiver LowMC key K
    size_t r_bytes;           // signer nonce r
    size_t op_bytes;          // BCGY opening op / sPRP randomness s
    size_t salt_bytes;        // MAYO salt in the witness
    size_t pkr_bytes;         // receiver public key pk_R
    size_t m_bytes;           // public message m
    size_t t_bytes;           // MAYO target bytes
    size_t s_bytes;           // MAYO preimage (encoded, no salt)
    size_t expanded_pk_bytes; // MAYO expanded public key
    size_t lowmc_gadgets;
    size_t rain_gadgets;
    size_t target_blocks;     // Rain calls in the target derivation
} nibs_instance_info;

bool nibs_instance_info_get(unsigned variant, unsigned level, unsigned speed, unsigned version,
                            nibs_instance_info* out);

// fs_context: 32 bytes absorbed into every Fiat-Shamir challenge. Callers bind
// the statement here, e.g. H("NIBS" || ids || vk || m).
// random_seed: random_seed_bytes of fresh randomness (hedged with the witness).
bool nibs_prove(unsigned variant, unsigned level, unsigned speed, unsigned version, uint8_t* proof,
                size_t proof_len, const uint8_t* random_seed, size_t random_seed_len,
                const uint8_t* expanded_pk, const uint8_t* m_pub, const uint8_t* s,
                const uint8_t* K, const uint8_t* op, const uint8_t* nonce, const uint8_t* salt,
                const uint8_t* fs_context);

bool nibs_verify(unsigned variant, unsigned level, unsigned speed, unsigned version,
                 const uint8_t* proof, size_t proof_len, const uint8_t* expanded_pk,
                 const uint8_t* m_pub, const uint8_t* fs_context);

// Testing aid: build the witness from the given secrets, optionally flip one
// witness bit (flip_bit < witness_bits; SIZE_MAX for none), evaluate the
// circuit and return the number of unsatisfied constraints (0 = the relation
// holds). Does not produce a proof.
size_t nibs_count_unsatisfied(unsigned variant, unsigned level, unsigned speed, unsigned version,
                              const uint8_t* expanded_pk, const uint8_t* m_pub, const uint8_t* s,
                              const uint8_t* K, const uint8_t* op, const uint8_t* nonce,
                              const uint8_t* salt, size_t flip_bit);

// Cleartext derivations (identical to what the circuit proves).
void nibs_derive_pkr(unsigned variant, unsigned level, const uint8_t* K, const uint8_t* op,
                     uint8_t* pkr);
void nibs_derive_message(unsigned variant, unsigned level, const uint8_t* K, const uint8_t* r,
                         uint8_t* m);
// MAYO target t = T(msg) for msg = M || salt, M = r || pk_R.
void nibs_target(unsigned level, const uint8_t* msg, size_t msg_len, uint8_t* t, size_t t_len);

// One RainHash-512 call (input 64 bytes; first outlen bytes of the output).
void rain_hash_512_7_c(uint8_t* output, size_t outlen, const uint8_t* input, size_t inlen);

// LowMC (see lowmc_plain/lowmc.hpp)
void nibs_lowmc_init(void);
unsigned nibs_lowmc_block_bytes(unsigned level);
unsigned nibs_lowmc_rounds(unsigned level);
void nibs_lowmc_encrypt(unsigned level, const uint8_t* key, const uint8_t* pt, uint8_t* ct);
void nibs_lowmc_decrypt(unsigned level, const uint8_t* key, const uint8_t* ct, uint8_t* pt);

#ifdef __cplusplus
}
#endif

#endif
