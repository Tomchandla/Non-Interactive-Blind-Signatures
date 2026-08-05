// Portions of this file are derived from the LowMC reference implementation:
// https://github.com/LowMC/lowmc
//
// Original work licensed under the MIT License.
// Adapted for the NIBS construction.

#ifndef NIBS_LOWMC_H
#define NIBS_LOWMC_H

#include <cstddef>
#include <cstdint>

#include "lowmc_params.hpp"

#ifdef __cplusplus
extern "C" {
#endif

void nibs_lowmc_init(void);

unsigned nibs_lowmc_param_level(void);

// ---------------------------------------------------------------------------
// Primitive
// ---------------------------------------------------------------------------

// ct = E_key(pt)
void nibs_lowmc_encrypt(const uint8_t key[NIBS_LOWMC_KEY_BYTES],
                        const uint8_t pt[NIBS_LOWMC_BLOCK_BYTES],
                        uint8_t ct[NIBS_LOWMC_BLOCK_BYTES]);

void nibs_lowmc_witness_states(const uint8_t key[NIBS_LOWMC_KEY_BYTES],
                               const uint8_t pt[NIBS_LOWMC_BLOCK_BYTES],
                               uint8_t states[NIBS_LOWMC_STATE_BYTES],
                               uint8_t ct[NIBS_LOWMC_BLOCK_BYTES]);

const uint8_t* nibs_lowmc_linmat(unsigned r);
const uint8_t* nibs_lowmc_keymat(unsigned r);
const uint8_t* nibs_lowmc_roundconst(unsigned r);

void nibs_derive_message(const uint8_t K[NIBS_LOWMC_KEY_BYTES],
                         const uint8_t r[NIBS_LOWMC_NONCE_BYTES],
                         uint8_t m[NIBS_LOWMC_MESSAGE_BYTES]);

void nibs_lowmc_witness_expand(const uint8_t K[NIBS_LOWMC_KEY_BYTES],
                               const uint8_t r[NIBS_LOWMC_NONCE_BYTES],
                               uint8_t out[NIBS_LOWMC_WITNESS_BYTES],
                               uint8_t m_out[NIBS_LOWMC_MESSAGE_BYTES]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NIBS_LOWMC_H
