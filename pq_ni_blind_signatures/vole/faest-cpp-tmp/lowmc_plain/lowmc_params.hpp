// lowmc_params.hpp -- LowMC instances for NIBS at NIST security levels 1, 3, 5.
//
// All three instances are compiled into the same library; the circuit and
// the cleartext code select one by NIST level (1, 3 or 5), which is tied to
// the VOLEitH security parameter lambda = 128 / 192 / 256.
//
// Parameters (n = k = lambda, full S-box layer, data complexity d = 2^64):
//   level 1: n = k = 128, m = 42 S-boxes (+2 identity bits), r = 13
//   level 3: n = k = 192, m = 64 S-boxes (+0 identity bits), r = 13
//   level 5: n = k = 256, m = 85 S-boxes (+1 identity bit),  r = 13
// The round numbers are the output of determine_rounds.py from the LowMC
// reference repository (https://github.com/LowMC/lowmc) for (n, m, d=64, k);
// the binding attack class for all three is "derivative + interpolation".

#ifndef NIBS_LOWMC_PARAMS_H
#define NIBS_LOWMC_PARAMS_H

#ifdef __cplusplus
#include <cstddef>

namespace nibs_lowmc
{

template <unsigned LEVEL> struct params;

template <> struct params<1>
{
    static constexpr unsigned BLOCK_BITS = 128;
    static constexpr unsigned KEY_BITS = 128;
    static constexpr unsigned BOXES = 42;
    static constexpr unsigned ROUNDS = 13;
    static constexpr unsigned DATA_LOG2 = 64;
};

template <> struct params<3>
{
    static constexpr unsigned BLOCK_BITS = 192;
    static constexpr unsigned KEY_BITS = 192;
    static constexpr unsigned BOXES = 64;
    static constexpr unsigned ROUNDS = 13;
    static constexpr unsigned DATA_LOG2 = 64;
};

template <> struct params<5>
{
    static constexpr unsigned BLOCK_BITS = 256;
    static constexpr unsigned KEY_BITS = 256;
    static constexpr unsigned BOXES = 85;
    static constexpr unsigned ROUNDS = 13;
    static constexpr unsigned DATA_LOG2 = 64;
};

template <unsigned LEVEL> struct derived : params<LEVEL>
{
    using P = params<LEVEL>;
    static constexpr unsigned IDENTITY_BITS = P::BLOCK_BITS - 3 * P::BOXES;
    static constexpr unsigned BLOCK_BYTES = P::BLOCK_BITS / 8;
    static constexpr unsigned KEY_BYTES = P::KEY_BITS / 8;
    static constexpr unsigned STATE_BYTES = P::ROUNDS * BLOCK_BYTES; // post-S-box states
    static constexpr unsigned AND_GATES = 3 * P::BOXES * P::ROUNDS;

    static_assert(3 * P::BOXES + IDENTITY_BITS == P::BLOCK_BITS);
    static_assert(IDENTITY_BITS < 3, "full S-box layer: identity part is a remainder");
    static_assert(P::BLOCK_BITS % 8 == 0 && P::KEY_BITS <= P::BLOCK_BITS);
};

constexpr unsigned level_of_bits(std::size_t lambda)
{
    return lambda == 128 ? 1 : lambda == 192 ? 3 : 5;
}

} // namespace nibs_lowmc
#endif

#endif // NIBS_LOWMC_PARAMS_H
