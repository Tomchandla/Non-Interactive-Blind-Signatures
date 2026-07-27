#ifndef PARAMETERS_LOWMC_NIBS_H
#define PARAMETERS_LOWMC_NIBS_H

// LowMC instances
constexpr std::size_t NIBS_LOWMC_N             = 256; 
constexpr std::size_t NIBS_LOWMC_K             = 256;
constexpr std::size_t NIBS_LOWMC_BOXES_C       = 85;
constexpr std::size_t NIBS_LOWMC_PRF_ROUNDS_C  = 13;

// Plaintext domain bytes
constexpr unsigned char NIBS_DOM_PK_C  = 0x01;  // GadA
constexpr unsigned char NIBS_DOM_M_C   = 0x02;  // GadM

// Byte sizes of protocol values
constexpr std::size_t NIBS_SKR_BYTES   = 32;
constexpr std::size_t NIBS_OPEN_BYTES  = 16;
constexpr std::size_t NIBS_NONCE_BYTES = 16;
constexpr std::size_t NIBS_PKR_BYTES   = 32;
constexpr std::size_t NIBS_M_BYTES     = 32;
constexpr std::size_t NIBS_PRESIG_MSG_BYTES = NIBS_PKR_BYTES + NIBS_NONCE_BYTES;

// LowMC witness region
constexpr std::size_t NIBS_SKR_BIT_OFF   = 0;
constexpr std::size_t NIBS_SKR_BITS      = 256;
constexpr std::size_t NIBS_OPEN_BIT_OFF  = NIBS_SKR_BIT_OFF + NIBS_SKR_BITS;
constexpr std::size_t NIBS_OPEN_BITS     = 128;
constexpr std::size_t NIBS_NONCE_BIT_OFF = NIBS_OPEN_BIT_OFF + NIBS_OPEN_BITS;
constexpr std::size_t NIBS_NONCE_BITS    = 128;

constexpr std::size_t NIBS_GADA_ST_OFF  = NIBS_NONCE_BIT_OFF + NIBS_NONCE_BITS;
constexpr std::size_t NIBS_GADA_ST_BITS = NIBS_LOWMC_PRF_ROUNDS_C * NIBS_LOWMC_N;
constexpr std::size_t NIBS_GADM_ST_OFF  = NIBS_GADA_ST_OFF + NIBS_GADA_ST_BITS;
constexpr std::size_t NIBS_GADM_ST_BITS = NIBS_LOWMC_PRF_ROUNDS_C * NIBS_LOWMC_N;
constexpr std::size_t NIBS_LOWMC_WITNESS_BITS = NIBS_GADM_ST_OFF + NIBS_GADM_ST_BITS;

// Rain region
constexpr std::size_t NIBS_GADGET_2_IN_OFF   = NIBS_LOWMC_WITNESS_BITS;

constexpr std::size_t NIBS_GAD2_B1_BIT_OFF   = NIBS_GADGET_2_IN_OFF;
constexpr std::size_t NIBS_GAD2_B1_PKR_OFF   = NIBS_GAD2_B1_BIT_OFF;
constexpr std::size_t NIBS_GAD2_B1_NONCE_OFF = NIBS_GAD2_B1_BIT_OFF + 256;
constexpr std::size_t NIBS_GAD2_B1_SALT_OFF  = NIBS_GAD2_B1_BIT_OFF + 384;

// block 1: in-block + NUM_ROUNDS states, then the chaining value h1
#define NIBS_GAD2_H1_OFF \
    (NIBS_GAD2_B1_BIT_OFF + VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1))

// block 2: in-block (salt tail | pad, XOR h1) + NUM_ROUNDS states, then t
#define NIBS_GAD2_B2_BIT_OFF   (NIBS_GAD2_H1_OFF + VOLERAINHASH_B)
#define NIBS_GAD2_B2_SALT_OFF  NIBS_GAD2_B2_BIT_OFF
#define NIBS_GADGET_2_OUT_OFF \
    (NIBS_GAD2_B2_BIT_OFF + VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1))

#define NIBS_MIXED_WITNESS_BITS (NIBS_GADGET_2_OUT_OFF + VOLERAINHASH_B)

#define NIBS_S_BIT_OFF NIBS_MIXED_WITNESS_BITS

constexpr std::size_t NIBS_GADGET_M_ST_OFF = (std::size_t)-1;
#endif // PARAMETERS_LOWMC_NIBS_H
