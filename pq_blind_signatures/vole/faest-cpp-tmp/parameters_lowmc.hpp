// parameters_lowmc.hpp
//
// NIBS witness layout for the MIXED LowMC + Rain circuit (BCGY24 generic
// construction, eprint 2024/614 App. B/D p.81, instantiated as:
//   PRF / commitment : LowMC   (GadA, GadM; Gad1 as LowMC-MMO compression)
//   MAYO msg hash    : Rain    (Gad2 -- kept from the Rain edition because
//                               Rain composes better with VOLEitH)
//   signature        : MAYO
//   NIZK             : VOLEitH/FAEST).
//
// Included from parameters.hpp inside the WITH_RAINHASH block, AFTER the
// VOLERAINHASH_* primitive constants (B, NUM_ROUNDS, RAIN_CAP16) -- it uses
// them for the Gad2 region.
//
// Witness layout (bit offsets from the start of the non-MAYO witness region;
// bytes are LSB-first packed: bit i <-> (bytes[i>>3] >> (i&7)) & 1):
//
//   [     0,   256)  skR          -- recipient PRF key K (256-bit LowMC key)
//   [   256,   384)  open         -- 128-bit commitment opening randomness s
//   [   384,   512)  nonce        -- 128-bit signer-sampled nonce
//   [   512,  3840)  GadA states  -- 13 rounds x 256 post-S-box bits (PRF)
//                                     pkR = E^PRF_K( PT(DOM_PK, open) )
//   [  3840,  9472)  Gad1 states  -- 22 rounds x 256              (HASH/MMO)
//                                     com = MMO(pkR, PT(DOM_COM, nonce))
//   [  9472, 12800)  GadM states  -- 13 rounds x 256 (PRF)
//                                     m   = E^PRF_K( PT(DOM_M, nonce) )
//   --- Rain Gad2 region (geometry identical to the Rain edition) ----------
//   [ 12800, 13312)  Gad2 in-blk  -- com(256) | salt(192, L1) | 0xff(64)
//   [ 13312, 16896)  Gad2 states  -- 7 x 512 post-S-box Rain state blocks
//   [ 16896, 17408)  Gad2 out-blk -- t in the first 256 bits
//   [ 17408, ....)   s            -- MAYO preimage (GF16 nibbles, packing
//                                     unchanged; loaded at
//                                     VOLERAINHASH_WITNESS_SIZE_BITS)
//
// NOT witnessed, by design: pkR, com (as a value), t's preimage chain inside
// LowMC, round keys, and m. They are linear functions of witnessed bits and
// public constants and exist only as wire expressions -- EXCEPT com, which
// must cross the LowMC->Rain seam: Gad2's loader consumes witness bits, so
// com is materialized in Gad2's in-block and bound to Gad1's output
// expression by 256 explicit GF(2) equality constraints (the seam).
//
// Binding elsewhere is structural, as in the all-LowMC draft: GadA and GadM
// consume the SAME skR wires as cipher key; GadA and Gad1/GadM share the
// open/nonce wires by offset; Gad1 takes GadA's output expression directly
// as its MMO chaining key. No equality constraints needed for those seams.

#ifndef PARAMETERS_LOWMC_NIBS_H
#define PARAMETERS_LOWMC_NIBS_H

// NOTE deliberately no #include here: this header is pulled in by
// parameters.hpp INSIDE namespace faest, so any include would inject its
// declarations into the namespace (std would become faest::std and break
// every subsequent standard-library include). std::size_t etc. are already
// visible at the inclusion point.

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

static_assert(NIBS_LOWMC_WITNESS_BITS == 12800,
              "LowMC region drifted from spec (1600 bytes)");
static_assert(NIBS_GADA_ST_OFF % 8 == 0 && NIBS_GAD1_ST_OFF % 8 == 0 &&
              NIBS_GADM_ST_OFF % 8 == 0,
              "LowMC state regions must be byte-aligned");

// --- Rain Gad2 region (bit offsets; geometry [in | 7 states | out]) ----------
// The names NIBS_GADGET_2_IN_OFF / NIBS_GADGET_2_OUT_OFF are load-bearing:
// enc_constraints_rainhash's generic branch derives the state/out offsets from
// the in-offset, and enc_constraints_mayo loads the MAYO target t from
// NIBS_GADGET_2_OUT_OFF. Only Gad2 uses the Rain path now.
constexpr std::size_t NIBS_GADGET_2_IN_OFF  = NIBS_LOWMC_WITNESS_BITS;      // 12800
// In-block content: com (bits 0..256, lanes 0-1), MAYO salt (24 bytes at L1,
// bits 256..448), 0xff fill (bits 448..512). Lanes 2-3 are witness-loaded
// together since the salt straddles the lane boundary.
constexpr std::size_t NIBS_GAD2_COM_BIT_OFF  = NIBS_GADGET_2_IN_OFF;
constexpr std::size_t NIBS_GAD2_SALT_BIT_OFF = NIBS_GADGET_2_IN_OFF + 256;

// NOTE: these two use VOLERAINHASH_B / VOLERAINHASH_NUM_ROUNDS from
// parameters.hpp (512 / 7); this header is included after them.
#define NIBS_GADGET_2_OUT_OFF \
    (NIBS_GADGET_2_IN_OFF + VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1))
#define NIBS_MIXED_WITNESS_BITS (NIBS_GADGET_2_OUT_OFF + VOLERAINHASH_B)
// = 12800 + 8*512 + 512 = 17408 bits = 2176 bytes

// MAYO preimage s starts right after the mixed region; its size and packing
// are unchanged (loaded at VOLERAINHASH_WITNESS_SIZE_BITS, which
// parameters.hpp now defines as NIBS_MIXED_WITNESS_BITS).
#define NIBS_S_BIT_OFF NIBS_MIXED_WITNESS_BITS

// Sentinel kept only so the Rain gadget helpers' gadget-M special case (which
// is never taken anymore -- GadM is LowMC) still compiles without edits.
constexpr std::size_t NIBS_GADGET_M_ST_OFF = (std::size_t)-1;

#endif // PARAMETERS_LOWMC_NIBS_H
