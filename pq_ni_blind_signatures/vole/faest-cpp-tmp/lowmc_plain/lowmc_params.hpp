// lowmc_params.hpp -- LowMC parameter sets for NIBS at NIST security
// levels 1, 3 and 5.
//
// Round counts are pulled from the LowMC reference repository, 
// https://github.com/LowMC/lowmc (MIT licensed), which implements the 
// round formula of "Ciphers for MPC and FHE", EUROCRYPT 2015

#ifndef NIBS_LOWMC_PARAMS_H
#define NIBS_LOWMC_PARAMS_H

#ifndef NIBS_LOWMC_LEVEL
#define NIBS_LOWMC_LEVEL 1
#endif

// ---------------------------------------------------------------------------
// Selected level
// ---------------------------------------------------------------------------

#if NIBS_LOWMC_LEVEL == 1

#define NIBS_LOWMC_LAMBDA 128
#define NIBS_LOWMC_BLOCK_BITS 128
#define NIBS_LOWMC_KEY_BITS 128
#define NIBS_LOWMC_BOXES 42
#define NIBS_LOWMC_IDENTITY_BITS 2
#define NIBS_LOWMC_DATA_LOG2 64
#define NIBS_LOWMC_ROUNDS 13
#define NIBS_LOWMC_MAYO_SET "MAYO1" // salt 24 B

#elif NIBS_LOWMC_LEVEL == 3

#define NIBS_LOWMC_LAMBDA 192
#define NIBS_LOWMC_BLOCK_BITS 192
#define NIBS_LOWMC_KEY_BITS 192
#define NIBS_LOWMC_BOXES 64
#define NIBS_LOWMC_IDENTITY_BITS 0
#define NIBS_LOWMC_DATA_LOG2 64
#define NIBS_LOWMC_ROUNDS 13
#define NIBS_LOWMC_MAYO_SET "MAYO3" // salt 32 B

#elif NIBS_LOWMC_LEVEL == 5

#define NIBS_LOWMC_LAMBDA 256
#define NIBS_LOWMC_BLOCK_BITS 256
#define NIBS_LOWMC_KEY_BITS 256
#define NIBS_LOWMC_BOXES 85
#define NIBS_LOWMC_IDENTITY_BITS 1
#define NIBS_LOWMC_DATA_LOG2 64
#define NIBS_LOWMC_ROUNDS 13
#define NIBS_LOWMC_MAYO_SET "MAYO5" // salt 40 B

#else
#error "NIBS_LOWMC_LEVEL must be 1, 3 or 5"
#endif

enum {
    // Byte widths.
    NIBS_LOWMC_BLOCK_BYTES = NIBS_LOWMC_BLOCK_BITS / 8, // 16 / 24 / 32
    NIBS_LOWMC_KEY_BYTES = NIBS_LOWMC_KEY_BITS / 8,     // K
    NIBS_LOWMC_ROW_BYTES = NIBS_LOWMC_BLOCK_BYTES,      // packed matrix row
    NIBS_LOWMC_NONCE_BYTES = NIBS_LOWMC_LAMBDA / 8,     // r, one full block
    NIBS_LOWMC_MESSAGE_BYTES = NIBS_LOWMC_BLOCK_BYTES,  // m, public
    NIBS_LOWMC_OPEN_BYTES = NIBS_LOWMC_LAMBDA / 8,      // op: Rain side only

    // Witness: one post-S-box state per round.
    NIBS_LOWMC_STATE_BYTES = NIBS_LOWMC_ROUNDS * NIBS_LOWMC_BLOCK_BYTES,

    // LowMC region of the VOLEitH witness: K || r || GadM states.
    NIBS_LOWMC_WITNESS_BYTES = NIBS_LOWMC_KEY_BYTES + NIBS_LOWMC_NONCE_BYTES +
                               NIBS_LOWMC_STATE_BYTES,
    NIBS_LOWMC_WITNESS_BITS = 8 * NIBS_LOWMC_WITNESS_BYTES,

    // Circuit cost
    NIBS_LOWMC_CONSTRAINTS = NIBS_LOWMC_ROUNDS * NIBS_LOWMC_BLOCK_BITS,
    NIBS_LOWMC_PUBLIC_CONSTRAINTS = NIBS_LOWMC_BLOCK_BITS,
    NIBS_LOWMC_AND_GATES = 3 * NIBS_LOWMC_BOXES * NIBS_LOWMC_ROUNDS,

    NIBS_LOWMC_MATRIX_BYTES =
        (2 * NIBS_LOWMC_ROUNDS + 1) * NIBS_LOWMC_BLOCK_BITS *
            NIBS_LOWMC_ROW_BYTES +
        NIBS_LOWMC_ROUNDS * NIBS_LOWMC_BLOCK_BYTES,
};

// Size checks
#ifdef __cplusplus
static_assert(3 * NIBS_LOWMC_BOXES + NIBS_LOWMC_IDENTITY_BITS ==
                  NIBS_LOWMC_BLOCK_BITS,
              "S-box layer plus identity part must cover the block exactly");
static_assert(NIBS_LOWMC_IDENTITY_BITS < 3,
              "identity part is the remainder of a full S-box layer");
static_assert(NIBS_LOWMC_BLOCK_BITS % 8 == 0,
              "block must be byte aligned: the packing helpers assume it");
static_assert(NIBS_LOWMC_KEY_BITS <= NIBS_LOWMC_BLOCK_BITS,
              "keyblock is stored in a block-wide bitset");
static_assert(8 * NIBS_LOWMC_NONCE_BYTES == NIBS_LOWMC_BLOCK_BITS,
              "r is the plaintext block verbatim; a mismatch means padding "
              "or a domain tag was reintroduced without updating the gadget");
#endif

#endif // NIBS_LOWMC_PARAMS_H
