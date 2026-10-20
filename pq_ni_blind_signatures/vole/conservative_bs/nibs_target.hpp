// nibs_target.hpp -- cleartext NIBS computations shared by the prover's
// witness builder and the FFI used by MAYO and the Rust protocol layer.
//
// This is the single source of truth for the target mode T and the receiver
// key derivations; the circuit (nibs_circuit.inc) mirrors it on wires.

#ifndef NIBS_TARGET_HPP
#define NIBS_TARGET_HPP

#include <algorithm>
#include <cstdint>
#include <cstring>

#include "lowmc_plain/lowmc.hpp"
#include "parameters.hpp"
#include "rainhash_plain/rain_hash.h"

namespace faest
{

constexpr std::size_t NIBS_RAIN_STATE_BYTES = NIBS_RAIN_STATE_BITS / 8; // 7 * 64

// One RainHash-512 call; if `states` is non-null the 7 S-box outputs are
// written there (the gadget's witness).
inline void nibs_rain(const uint8_t in[64], uint8_t out[64], uint8_t* states)
{
    if (states)
        rain_hash_with_sbox_output(in, states, out);
    else
        rain_hash(in, out);
}

inline std::size_t nibs_rate_bytes(unsigned level)
{
    const std::size_t lambda = level == 1 ? 128 : level == 3 ? 192 : 256;
    return (VOLERAINHASH_B - lambda - 64) / 8;
}

// Number of Rain calls T makes for a msg_len-byte input and t_len-byte output.
inline std::size_t nibs_target_blocks(unsigned level, std::size_t msg_len, std::size_t t_len)
{
    const std::size_t rate = nibs_rate_bytes(level);
    std::size_t blocks = 1;
    if (msg_len > VOLERAINHASH_B_BYTES)
        blocks += (msg_len - VOLERAINHASH_B_BYTES + rate - 1) / rate;
    return blocks + (t_len > VOLERAINHASH_B_BYTES ? 1 : 0);
}

// t = T(msg):
//   h = f(msg[0:64] || 0xff..)
//   for every further chunk of at most RATE bytes: h = f((chunk || 0xff..) xor h)
//   t = h[0:t_len]                         if t_len <= 64
//   t = h || f(h)[0:t_len-64]              otherwise (MAYO5)
// states (optional) receives NIBS_RAIN_STATE_BYTES per Rain call, in order.
inline void nibs_target_hash(unsigned level, const uint8_t* msg, std::size_t msg_len, uint8_t* t,
                             std::size_t t_len, uint8_t* states)
{
    const std::size_t rate = nibs_rate_bytes(level);
    uint8_t blk[64], h[64];
    auto next_states = [&]()
    {
        uint8_t* p = states;
        if (states)
            states += NIBS_RAIN_STATE_BYTES;
        return p;
    };

    const std::size_t first = std::min<std::size_t>(64, msg_len);
    memset(blk, 0xff, 64);
    memcpy(blk, msg, first);
    nibs_rain(blk, h, next_states());
    for (std::size_t pos = first; pos < msg_len; pos += rate)
    {
        const std::size_t n = std::min(rate, msg_len - pos);
        memset(blk, 0xff, 64);
        memcpy(blk, msg + pos, n);
        for (int i = 0; i < 64; ++i)
            blk[i] ^= h[i];
        nibs_rain(blk, h, next_states());
    }
    memcpy(t, h, std::min<std::size_t>(64, t_len));
    if (t_len > 64)
    {
        uint8_t h2[64];
        nibs_rain(h, h2, next_states());
        memcpy(t + 64, h2, t_len - 64);
    }
}

// BCGY receiver key: pk_R = f(op || K || 0xff..)[0 : 2 lambda].
inline void nibs_bcgy_pkr(unsigned level, const uint8_t* op, const uint8_t* K, uint8_t* pkr,
                          uint8_t* states)
{
    const std::size_t lb = level == 1 ? 16 : level == 3 ? 24 : 32;
    uint8_t in[64], out[64];
    memset(in, 0xff, 64);
    memcpy(in, op, lb);
    memcpy(in + lb, K, lb);
    nibs_rain(in, out, states);
    memcpy(pkr, out, 2 * lb);
}

// sPRP receiver key: pk_R = P_K(0||c0) || P_K(0||c1) with c0 = 0, c1 = 1 (the
// top bit of every pk input is the domain bit 0). states (optional) receives
// both LowMC witnesses back to back.
inline void nibs_sprp_pkr(unsigned level, const uint8_t* K, uint8_t* pkr, uint8_t* states)
{
    const std::size_t lb = nibs_lowmc_block_bytes(level);
    const std::size_t st = nibs_lowmc_rounds(level) * lb;
    uint8_t c[32] = {0};
    nibs_lowmc_witness_states(level, K, c, states, pkr);
    c[0] = 1;
    nibs_lowmc_witness_states(level, K, c, states ? states + st : nullptr, pkr + lb);
}

// Message derivation. BCGY: m = LowMC_K(r). sPRP: m = LowMC_K(r with its top
// bit set to the domain bit 1).
inline void nibs_message(unsigned level, bool sprp, const uint8_t* K, const uint8_t* r, uint8_t* m,
                         uint8_t* states)
{
    const std::size_t lb = nibs_lowmc_block_bytes(level);
    uint8_t pt[32];
    memcpy(pt, r, lb);
    if (sprp)
        pt[lb - 1] |= 0x80;
    nibs_lowmc_witness_states(level, K, pt, states, m);
}

} // namespace faest

#endif
