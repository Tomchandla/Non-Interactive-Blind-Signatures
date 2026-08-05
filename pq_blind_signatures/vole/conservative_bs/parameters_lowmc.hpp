#ifndef PARAMETERS_LOWMC_NIBS_H
#define PARAMETERS_LOWMC_NIBS_H

constexpr std::size_t NIBS_K_BITS = NIBS_LOWMC_KEY_BITS;
constexpr std::size_t NIBS_R_BITS = 8 * NIBS_LOWMC_NONCE_BYTES;
constexpr std::size_t NIBS_OP_BITS = NIBS_LOWMC_LAMBDA;
constexpr std::size_t NIBS_M_BITS = NIBS_LOWMC_BLOCK_BITS;
constexpr std::size_t NIBS_PKR_BITS = 256;
constexpr std::size_t NIBS_SALT_BITS = 192;

constexpr std::size_t NIBS_K_BYTES = NIBS_K_BITS / 8;
constexpr std::size_t NIBS_R_BYTES = NIBS_R_BITS / 8;
constexpr std::size_t NIBS_OP_BYTES = NIBS_OP_BITS / 8;
constexpr std::size_t NIBS_M_BYTES = NIBS_M_BITS / 8;
constexpr std::size_t NIBS_PKR_BYTES = NIBS_PKR_BITS / 8;
constexpr std::size_t NIBS_NONCE_BYTES = NIBS_R_BYTES;

constexpr std::size_t NIBS_RAIN_GADGET_BITS =
    VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 2);

// witness layout
constexpr std::size_t NIBS_K_BIT_OFF = 0;
constexpr std::size_t NIBS_R_BIT_OFF = NIBS_K_BIT_OFF + NIBS_K_BITS;
constexpr std::size_t NIBS_GADM_ST_OFF = NIBS_R_BIT_OFF + NIBS_R_BITS;
constexpr std::size_t NIBS_GADM_ST_BITS =
    NIBS_LOWMC_ROUNDS * NIBS_LOWMC_BLOCK_BITS;
constexpr std::size_t NIBS_LOWMC_REGION_BITS =
    NIBS_GADM_ST_OFF + NIBS_GADM_ST_BITS;

constexpr std::size_t NIBS_GADA_IN_OFF = NIBS_LOWMC_REGION_BITS;
constexpr std::size_t NIBS_GADA_OP_OFF = NIBS_GADA_IN_OFF;
constexpr std::size_t NIBS_GADA_K_OFF = NIBS_GADA_IN_OFF + NIBS_OP_BITS;
constexpr std::size_t NIBS_GADA_OUT_OFF =
    NIBS_GADA_IN_OFF + VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1);

constexpr std::size_t NIBS_GAD2_B1_BIT_OFF =
    NIBS_GADA_IN_OFF + NIBS_RAIN_GADGET_BITS;
constexpr std::size_t NIBS_GAD2_B1_NONCE_OFF =
    NIBS_GAD2_B1_BIT_OFF + NIBS_PKR_BITS;
constexpr std::size_t NIBS_GAD2_B1_SALT_OFF =
    NIBS_GAD2_B1_NONCE_OFF + NIBS_R_BITS;
constexpr std::size_t NIBS_GAD2_H1_OFF =
    NIBS_GAD2_B1_BIT_OFF + VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1);

constexpr std::size_t NIBS_GAD2_B2_BIT_OFF =
    NIBS_GAD2_B1_BIT_OFF + NIBS_RAIN_GADGET_BITS;
constexpr std::size_t NIBS_GADGET_2_OUT_OFF =
    NIBS_GAD2_B2_BIT_OFF + VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1);

constexpr std::size_t NIBS_MIXED_WITNESS_BITS =
    NIBS_GAD2_B2_BIT_OFF + NIBS_RAIN_GADGET_BITS;
constexpr std::size_t NIBS_S_BIT_OFF = NIBS_MIXED_WITNESS_BITS;

constexpr std::size_t NIBS_SEAM_CONSTRAINTS = 1 + 2 + 1;
constexpr std::size_t NIBS_PUBLIC_M_CONSTRAINTS = NIBS_M_BITS;

// drift guards for testing
static_assert(NIBS_LOWMC_REGION_BITS == 8 * NIBS_LOWMC_WITNESS_BYTES,
              "circuit LowMC region disagrees with lowmc_params.hpp");
static_assert(NIBS_R_BITS == NIBS_LOWMC_BLOCK_BITS,
              "r must be exactly one LowMC block: no padding, no domain tag");
static_assert(NIBS_OP_BITS + NIBS_K_BITS <= VOLERAINHASH_B,
              "GadA input op | K must fit one Rain block");
static_assert(NIBS_PKR_BITS + NIBS_R_BITS + 128 == VOLERAINHASH_B,
              "B1 = c | r | salt[0:16] must fill one Rain block exactly");
static_assert(NIBS_OP_BITS % 128 == 0 && NIBS_K_BITS % 128 == 0 &&
              NIBS_R_BITS % 128 == 0,
              "lane-aligned layout: op/K/r must be multiples of a Rain lane");
static_assert((NIBS_GADA_IN_OFF % 8 == 0) && (NIBS_GAD2_B1_BIT_OFF % 8 == 0),
              "witness regions must be byte-aligned for get_witness_nibs");

#endif // PARAMETERS_LOWMC_NIBS_H
