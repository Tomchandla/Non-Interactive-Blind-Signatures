#ifndef PARAMETERS_LOWMC_NIBS_H
#define PARAMETERS_LOWMC_NIBS_H

// This header is pulled in by parameters.hpp INSIDE namespace faest

// --- LowMC instances (must match lowmc_plain/lowmc.hpp) ---------------------
constexpr std::size_t NIBS_LOWMC_N             = 256;  // block bits
constexpr std::size_t NIBS_LOWMC_K             = 256;  // key bits
constexpr std::size_t NIBS_LOWMC_BOXES_C       = 85;   // 255 S-box bits + 1 id
constexpr std::size_t NIBS_LOWMC_PRF_ROUNDS_C  = 13;   // d = 2^64
constexpr std::size_t NIBS_LOWMC_HASH_ROUNDS_C = 22;   // d = 2^256 (max data)

// --- Plaintext domain bytes (byte 0 of the 32-byte plaintext) ---------------
constexpr unsigned char NIBS_DOM_PK_C  = 0x01;  // GadA
constexpr unsigned char NIBS_DOM_M_C   = 0x02;  // GadM
constexpr unsigned char NIBS_DOM_COM_C = 0x03;  // Gad1

// --- Byte sizes of protocol values ------------------------------------------
constexpr std::size_t NIBS_SKR_BYTES   = 32;  // full 256-bit LowMC key
constexpr std::size_t NIBS_OPEN_BYTES  = 16;  // commitment opening randomness
constexpr std::size_t NIBS_NONCE_BYTES = 16;  // signer-sampled nonce
constexpr std::size_t NIBS_PKR_BYTES   = 32;
constexpr std::size_t NIBS_M_BYTES     = 32;

// --- LowMC witness region (bit offsets) --------------------------------------
constexpr std::size_t NIBS_SKR_BIT_OFF   = 0;
constexpr std::size_t NIBS_SKR_BITS      = 256;

constexpr std::size_t NIBS_OPEN_BIT_OFF  = NIBS_SKR_BIT_OFF + NIBS_SKR_BITS;
constexpr std::size_t NIBS_OPEN_BITS     = 128;

constexpr std::size_t NIBS_NONCE_BIT_OFF = NIBS_OPEN_BIT_OFF + NIBS_OPEN_BITS;
constexpr std::size_t NIBS_NONCE_BITS    = 128;

constexpr std::size_t NIBS_GADA_ST_OFF  = NIBS_NONCE_BIT_OFF + NIBS_NONCE_BITS;
constexpr std::size_t NIBS_GADA_ST_BITS = NIBS_LOWMC_PRF_ROUNDS_C * NIBS_LOWMC_N;

constexpr std::size_t NIBS_GAD1_ST_OFF  = NIBS_GADA_ST_OFF + NIBS_GADA_ST_BITS;
constexpr std::size_t NIBS_GAD1_ST_BITS = NIBS_LOWMC_HASH_ROUNDS_C * NIBS_LOWMC_N;

constexpr std::size_t NIBS_GADM_ST_OFF  = NIBS_GAD1_ST_OFF + NIBS_GAD1_ST_BITS;
constexpr std::size_t NIBS_GADM_ST_BITS = NIBS_LOWMC_PRF_ROUNDS_C * NIBS_LOWMC_N;

constexpr std::size_t NIBS_LOWMC_WITNESS_BITS =
    NIBS_GADM_ST_OFF + NIBS_GADM_ST_BITS;

// ------------------------- Rain Gad2 region  ---------------------------------
constexpr std::size_t NIBS_GADGET_2_IN_OFF  = NIBS_LOWMC_WITNESS_BITS;      // 12800
// In-block content: com (bits 0..256, lanes 0-1), MAYO salt (24 bytes at L1,
// bits 256..448), 0xff fill (bits 448..512). Lanes 2-3 are witness-loaded
// together since the salt straddles the lane boundary.
constexpr std::size_t NIBS_GAD2_COM_BIT_OFF  = NIBS_GADGET_2_IN_OFF;
constexpr std::size_t NIBS_GAD2_SALT_BIT_OFF = NIBS_GADGET_2_IN_OFF + 256;

// These two use VOLERAINHASH_B / VOLERAINHASH_NUM_ROUNDS from
// parameters.hpp (512 / 7); this header is included after them.
#define NIBS_GADGET_2_OUT_OFF \
    (NIBS_GADGET_2_IN_OFF + VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1))
#define NIBS_MIXED_WITNESS_BITS (NIBS_GADGET_2_OUT_OFF + VOLERAINHASH_B)

// MAYO preimage s starts right after the mixed region; its size and packing
// are unchanged (loaded at VOLERAINHASH_WITNESS_SIZE_BITS, which
// parameters.hpp now defines as NIBS_MIXED_WITNESS_BITS).
#define NIBS_S_BIT_OFF NIBS_MIXED_WITNESS_BITS

// Sentinel kept only so the Rain gadget helpers' gadget-M special case (which
// is never taken anymore -- GadM is LowMC) still compiles without edits.
constexpr std::size_t NIBS_GADGET_M_ST_OFF = (std::size_t)-1;

#endif // PARAMETERS_LOWMC_NIBS_H
