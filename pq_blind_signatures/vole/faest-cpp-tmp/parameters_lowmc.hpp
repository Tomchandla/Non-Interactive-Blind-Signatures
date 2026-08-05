#ifndef PARAMETERS_LOWMC_NIBS_H
#define PARAMETERS_LOWMC_NIBS_H

constexpr std::size_t NIBS_K_BITS     = NIBS_LOWMC_KEY_BITS;    // 128/192/256
constexpr std::size_t NIBS_R_BITS     = NIBS_LOWMC_NONCE_BITS;  // r
constexpr std::size_t NIBS_OP_BITS    = NIBS_LOWMC_LAMBDA;      // op
constexpr std::size_t NIBS_M_BITS     = NIBS_LOWMC_BLOCK_BITS;  // m, public
constexpr std::size_t NIBS_PKR_BITS   = 256;                    // c, Rain out
constexpr std::size_t NIBS_SALT_BITS  = 192;                    // MAYO1 salt

constexpr std::size_t NIBS_RAIN_BLOCK_BITS =
    VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1);
constexpr std::size_t NIBS_RAIN_CHAIN_BITS(std::size_t blocks)
{
    return blocks * NIBS_RAIN_BLOCK_BITS + VOLERAINHASH_B;
}

// GadA: c = RainHash(op || K || fill)
constexpr std::size_t NIBS_GADA_IN_BITS = NIBS_OP_BITS + NIBS_K_BITS;
constexpr std::size_t NIBS_GADA_BLOCKS =
    (NIBS_GADA_IN_BITS + VOLERAINHASH_B - 1) / VOLERAINHASH_B;

// Gad2: t = RainHash(c || r || salt || fill)
constexpr std::size_t NIBS_GAD2_IN_BITS =
    NIBS_PKR_BITS + NIBS_R_BITS + NIBS_SALT_BITS;
constexpr std::size_t NIBS_GAD2_BLOCKS =
    (NIBS_GAD2_IN_BITS + VOLERAINHASH_B - 1) / VOLERAINHASH_B;

// --- witness layout ----------------------------------------------------------
// [ LowMC region ][ GadA chain ][ Gad2 chain ][ MAYO s ]
constexpr std::size_t NIBS_K_BIT_OFF     = 0;
constexpr std::size_t NIBS_R_BIT_OFF     = NIBS_K_BIT_OFF + NIBS_K_BITS;
constexpr std::size_t NIBS_GADM_ST_OFF   = NIBS_R_BIT_OFF + NIBS_R_BITS;
constexpr std::size_t NIBS_GADM_ST_BITS  =
    NIBS_LOWMC_ROUNDS * NIBS_LOWMC_BLOCK_BITS;
constexpr std::size_t NIBS_LOWMC_REGION_BITS =
    NIBS_GADM_ST_OFF + NIBS_GADM_ST_BITS;

constexpr std::size_t NIBS_GADA_IN_OFF   = NIBS_LOWMC_REGION_BITS;
constexpr std::size_t NIBS_GADA_OP_OFF   = NIBS_GADA_IN_OFF;
constexpr std::size_t NIBS_GADA_K_OFF    = NIBS_GADA_IN_OFF + NIBS_OP_BITS;
constexpr std::size_t NIBS_GADA_OUT_OFF  =
    NIBS_GADA_IN_OFF + NIBS_GADA_BLOCKS * NIBS_RAIN_BLOCK_BITS;

constexpr std::size_t NIBS_GAD2_IN_OFF   =
    NIBS_GADA_IN_OFF + NIBS_RAIN_CHAIN_BITS(NIBS_GADA_BLOCKS);
constexpr std::size_t NIBS_GAD2_PKR_OFF  = NIBS_GAD2_IN_OFF;
constexpr std::size_t NIBS_GAD2_R_OFF    = NIBS_GAD2_IN_OFF + NIBS_PKR_BITS;
constexpr std::size_t NIBS_GAD2_SALT_OFF = NIBS_GAD2_R_OFF + NIBS_R_BITS;
constexpr std::size_t NIBS_GAD2_OUT_OFF  =
    NIBS_GAD2_IN_OFF + NIBS_GAD2_BLOCKS * NIBS_RAIN_BLOCK_BITS;

constexpr std::size_t NIBS_MIXED_WITNESS_BITS =
    NIBS_GAD2_IN_OFF + NIBS_RAIN_CHAIN_BITS(NIBS_GAD2_BLOCKS);
constexpr std::size_t NIBS_S_BIT_OFF = NIBS_MIXED_WITNESS_BITS;


constexpr std::size_t NIBS_SEAM_K_CONSTRAINTS   = NIBS_K_BITS;
constexpr std::size_t NIBS_SEAM_PKR_CONSTRAINTS = NIBS_PKR_BITS;
constexpr std::size_t NIBS_SEAM_R_CONSTRAINTS   = NIBS_R_BITS;
constexpr std::size_t NIBS_PUBLIC_M_CONSTRAINTS = NIBS_M_BITS;

// --- drift guards ------------------------------------------------------------
static_assert(NIBS_LOWMC_REGION_BITS == 8 * NIBS_LOWMC_WITNESS_BYTES,
              "circuit LowMC region disagrees with lowmc_params.hpp");
static_assert(NIBS_R_BITS == NIBS_LOWMC_BLOCK_BITS,
              "r must be exactly one LowMC block: no padding, no domain tag");
static_assert(NIBS_GADA_IN_BITS <= NIBS_GADA_BLOCKS * VOLERAINHASH_B,
              "GadA in-block overflows its Rain blocks");
static_assert(NIBS_GAD2_IN_BITS <= NIBS_GAD2_BLOCKS * VOLERAINHASH_B,
              "Gad2 in-block overflows its Rain blocks");

#endif // PARAMETERS_LOWMC_NIBS_H
