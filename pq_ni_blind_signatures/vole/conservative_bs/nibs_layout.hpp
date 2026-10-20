// nibs_layout.hpp -- sizes and VOLEitH witness layout for every NIBS variant
// at every NIST level. Included at the end of parameters.hpp.
//
// Notation: lambda in {128, 192, 256}; Rain = RainHash-512 with 7 rounds,
// f(x) = pi(x) xor x; LowMC = the level's LowMC instance (n = k = lambda).
//
//   variant     pk_R (2*lambda bits)                 message m (lambda bits)
//   BCGY        Rain(op || K || 0xff..)[0 : 2 lambda] LowMC_K(r)
//   sPRP        LowMC_K(0||c0) || LowMC_K(0||c1)      LowMC_K(1||r[0:lambda-1])
//
//   MAYO mode   presignature                     target t
//   standard    MAYO.Sign(sk, r||pk_R) incl salt  T(r || pk_R || salt)
//   One-More    MAYO.SPre(sk, T(r || pk_R))      T(r || pk_R)
//
// T is the sponge-like Rain mode implemented in nibs_target.hpp: the first
// block absorbs up to 512 message bits, every further block XORs at most
// RATE = 512 - lambda - 64 message bits (padded with 0xff) into the previous
// output, and one extra block f(h) is squeezed if MAYO's target is longer
// than 512 bits (MAYO5 only). Every chained block therefore carries at least
// lambda + 64 fixed bits; the fixed-length inputs make the mode unambiguous.
//
// The signed message is encoded nonce first, M = r || pk_R. With a capacity
// of c = lambda + 64 bits, two chains can be merged after a birthday search
// on c bits (2^{c/2}); if a block before the nonce were receiver-controlled
// (pk_R fills the whole first block at lambda = 256), a malicious receiver
// could precompute pk_R != pk_R' whose chaining values agree on the capacity,
// cancel the rate difference in the nonce block, and turn one presignature
// into two signed messages with ~2^160 work at level 5. With r in the first
// block every chaining value depends on the signer's fresh randomness, and
// moving an issued presignature to another message is a second-preimage
// problem on >= c bits.
//
// Witness (bit offsets, all byte aligned), in this order:
//   K | r | op (BCGY only) | salt (standard MAYO only)
//   | LowMC states for m | LowMC states for pk_R halves (sPRP only)
//   | Rain states for pk_R (BCGY only) | Rain states for T (one per block)
//   | MAYO preimage s
// A LowMC gadget commits its ROUNDS post-S-box states; a Rain gadget commits
// its 7 post-S-box states (inputs and outputs are linear in committed values
// and are computed as wires, so they are not committed again).

#ifndef NIBS_LAYOUT_HPP
#define NIBS_LAYOUT_HPP

#include "lowmc_plain/lowmc_params.hpp"

namespace faest
{

constexpr std::size_t NIBS_RAIN_STATE_BITS = VOLERAINHASH_B * VOLERAINHASH_NUM_ROUNDS;

template <secpar S> struct nibs_level
{
    static constexpr std::size_t LAMBDA = secpar_to_bits(S);
    static constexpr unsigned LEVEL = nibs_lowmc::level_of_bits(LAMBDA);
    using lowmc = nibs_lowmc::derived<LEVEL>;
    static_assert(lowmc::BLOCK_BITS == LAMBDA && lowmc::KEY_BITS == LAMBDA);

    // Chained Rain blocks carry at least LAMBDA + 64 fixed (0xff) bits.
    static constexpr std::size_t RATE_BYTES = (VOLERAINHASH_B - LAMBDA - 64) / 8;
    // Lane coordinates per 128-bit Rain lane inside F_{2^lambda}:
    // F_{2^128} embeds in F_{2^128} and F_{2^256}, but at lambda = 192 only
    // its F_{2^64} subfield does, so a lane becomes two coordinates.
    static constexpr std::size_t LANE_COORDS = (LAMBDA == 192) ? 2 : 1;
    // MAYO target bytes (m nibbles)
    static constexpr std::size_t T_BYTES = (4 * VOLEMAYO_M<S> + 7) / 8;
};

template <secpar S, owf O> struct nibs_layout
{
    using L = nibs_level<S>;
    static constexpr std::size_t LAMBDA = L::LAMBDA;
    static constexpr bool SPRP = nibs_is_sprp(O);
    static constexpr bool OMM = nibs_is_omm(O);

    // ---- object sizes (bytes) --------------------------------------------
    static constexpr std::size_t K_BYTES = LAMBDA / 8;
    static constexpr std::size_t R_BYTES = LAMBDA / 8;
    static constexpr std::size_t OP_BYTES = SPRP ? 0 : LAMBDA / 8;
    static constexpr std::size_t SALT_BYTES = OMM ? 0 : VOLEMAYO_SALT_BYTES<S>;
    static constexpr std::size_t PKR_BYTES = 2 * LAMBDA / 8;
    static constexpr std::size_t M_BYTES = LAMBDA / 8;
    static constexpr std::size_t T_BYTES = L::T_BYTES;

    // ---- target hash T ---------------------------------------------------
    static constexpr std::size_t T_MSG_BYTES = PKR_BYTES + R_BYTES + SALT_BYTES;
    static constexpr std::size_t T_ABSORB_BLOCKS =
        1 + (T_MSG_BYTES > VOLERAINHASH_B_BYTES
                 ? (T_MSG_BYTES - VOLERAINHASH_B_BYTES + L::RATE_BYTES - 1) / L::RATE_BYTES
                 : 0);
    static constexpr std::size_t T_SQUEEZE_BLOCKS = T_BYTES > VOLERAINHASH_B_BYTES ? 1 : 0;
    static constexpr std::size_t T_BLOCKS = T_ABSORB_BLOCKS + T_SQUEEZE_BLOCKS;
    static_assert(T_BYTES <= 2 * VOLERAINHASH_B_BYTES);

    // ---- gadget counts ---------------------------------------------------
    static constexpr std::size_t LOWMC_GADGETS = SPRP ? 3 : 1;
    static constexpr std::size_t RAIN_GADGETS = (SPRP ? 0 : 1) + T_BLOCKS;
    static constexpr std::size_t LOWMC_STATE_BITS = L::lowmc::ROUNDS * LAMBDA;

    // ---- witness offsets (bits) -----------------------------------------
    static constexpr std::size_t K_OFF = 0;
    static constexpr std::size_t R_OFF = K_OFF + 8 * K_BYTES;
    static constexpr std::size_t OP_OFF = R_OFF + 8 * R_BYTES;
    static constexpr std::size_t SALT_OFF = OP_OFF + 8 * OP_BYTES;
    static constexpr std::size_t LOWMC_M_OFF = SALT_OFF + 8 * SALT_BYTES;
    static constexpr std::size_t LOWMC_PK0_OFF = LOWMC_M_OFF + LOWMC_STATE_BITS; // sPRP
    static constexpr std::size_t LOWMC_PK1_OFF = LOWMC_PK0_OFF + LOWMC_STATE_BITS; // sPRP
    static constexpr std::size_t GADA_OFF = LOWMC_M_OFF + LOWMC_GADGETS * LOWMC_STATE_BITS; // BCGY
    static constexpr std::size_t T_OFF = GADA_OFF + (SPRP ? 0 : NIBS_RAIN_STATE_BITS);
    static constexpr std::size_t WITNESS_BITS = T_OFF + T_BLOCKS * NIBS_RAIN_STATE_BITS;
    static constexpr std::size_t WITNESS_BYTES = WITNESS_BITS / 8;
    static constexpr std::size_t S_OFF = WITNESS_BITS; // MAYO preimage follows

    static_assert(WITNESS_BITS % 8 == 0);
    static_assert(SPRP || 8 * (OP_BYTES + K_BYTES) <= VOLERAINHASH_B,
                  "BCGY commitment input op || K must fit one Rain block");

    // ---- constraints emitted ---------------------------------------------
    //  LowMC: ROUNDS * lambda each (3 per S-box + identity bits)
    //  public m: lambda
    //  Rain: 7 S-boxes * 4 lanes * LANE_COORDS each
    //  MAYO: 1 (all equations batched with a random embedding)
    static constexpr std::size_t NUM_CONSTRAINTS = LOWMC_GADGETS * LOWMC_STATE_BITS + LAMBDA +
                                                   RAIN_GADGETS * VOLERAINHASH_NUM_ROUNDS * 4 *
                                                       L::LANE_COORDS +
                                                   1;
};

} // namespace faest

#endif
