#ifndef NIBS_LOWMC_H
#define NIBS_LOWMC_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    NIBS_LOWMC_PRF = 0,
};

enum {
    NIBS_LOWMC_BLOCK_BYTES = 32,
    NIBS_LOWMC_KEY_BYTES   = 32,
    NIBS_LOWMC_BOXES       = 85,   // full S-box layer: 255 bits + 1 identity bit
    NIBS_LOWMC_PRF_ROUNDS  = 13,
};

void nibs_lowmc_init(void);

unsigned nibs_lowmc_rounds(int inst);

void nibs_lowmc_encrypt(int inst,
                        const uint8_t key[NIBS_LOWMC_KEY_BYTES],
                        const uint8_t pt[NIBS_LOWMC_BLOCK_BYTES],
                        uint8_t ct[NIBS_LOWMC_BLOCK_BYTES]);

void nibs_lowmc_witness_states(int inst,
                               const uint8_t key[NIBS_LOWMC_KEY_BYTES],
                               const uint8_t pt[NIBS_LOWMC_BLOCK_BYTES],
                               uint8_t* states,
                               uint8_t ct[NIBS_LOWMC_BLOCK_BYTES]);

const uint8_t* nibs_lowmc_linmat(int inst, unsigned r);
const uint8_t* nibs_lowmc_keymat(int inst, unsigned r);
const uint8_t* nibs_lowmc_roundconst(int inst, unsigned r);


enum {
    NIBS_DOM_PK  = 0x01,
    NIBS_DOM_M   = 0x02, 
    NIBS_LOWMC_OPEN_BYTES  = 16,
    NIBS_LOWMC_NONCE_BYTES = 16,
};

void nibs_lowmc_build_pt(uint8_t dom, const uint8_t* payload16,
                         uint8_t pt[NIBS_LOWMC_BLOCK_BYTES]);

void nibs_derive_pkr(const uint8_t skR[32], const uint8_t open[16],
                     uint8_t pkR[32]);
void nibs_derive_message(const uint8_t skR[32], const uint8_t nonce[16],
                         uint8_t m[32]);

enum { NIBS_LOWMC_WITNESS_BYTES = 32 + 16 + 16 + (13 + 13) * 32 };
void nibs_lowmc_witness_expand(const uint8_t skR[32],
                               const uint8_t open[16],
                               const uint8_t nonce[16],
                               uint8_t out[NIBS_LOWMC_WITNESS_BYTES],
                               uint8_t pkr_out[32]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NIBS_LOWMC_H
