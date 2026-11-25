// Portions of this file are derived from the LowMC reference implementation:
// https://github.com/LowMC/lowmc
//
// Original work licensed under the MIT License.
// Adapted for the NIBS construction.

#ifndef NIBS_LOWMC_H
#define NIBS_LOWMC_H

#include <stddef.h>
#include <stdint.h>

#include "lowmc_params.hpp"

#ifdef __cplusplus
extern "C" {
#endif

// Instantiate all three LowMC instances (idempotent, thread safe).
void nibs_lowmc_init(void);

// level is the NIST level: 1, 3 or 5. Keys and blocks are lambda/8 bytes,
// bit i of a block is (bytes[i/8] >> (i%8)) & 1.
unsigned nibs_lowmc_block_bytes(unsigned level);
unsigned nibs_lowmc_rounds(unsigned level);

// ct = E_key(pt)
void nibs_lowmc_encrypt(unsigned level, const uint8_t* key, const uint8_t* pt, uint8_t* ct);

// pt = E_key^{-1}(ct). LowMC is a keyed permutation, so the inverse exists and
// is efficiently computable from the key; the sPRP inverse oracle is this.
void nibs_lowmc_decrypt(unsigned level, const uint8_t* key, const uint8_t* ct, uint8_t* pt);

// Encrypt and record the post-S-box state of every round (the VOLEitH
// witness for one LowMC gadget). states holds rounds * block_bytes bytes.
void nibs_lowmc_witness_states(unsigned level, const uint8_t* key, const uint8_t* pt,
                               uint8_t* states, uint8_t* ct);

#ifdef __cplusplus
} // extern "C"

namespace nibs_lowmc
{
// Flattened public matrices for the circuit (row-major, block_bytes per row).
template <unsigned LEVEL> const uint8_t* linmat(unsigned r);     // r < ROUNDS
template <unsigned LEVEL> const uint8_t* keymat(unsigned r);     // r <= ROUNDS
template <unsigned LEVEL> const uint8_t* roundconst(unsigned r); // r < ROUNDS
} // namespace nibs_lowmc
#endif

#endif // NIBS_LOWMC_H
