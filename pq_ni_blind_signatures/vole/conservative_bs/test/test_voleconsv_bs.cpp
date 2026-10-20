// Unit tests for the cleartext building blocks of the NIBS circuits.
// End-to-end prove/verify tests live in the Rust crate (tests/nibs.rs).

#include <array>
#include <cstring>
#include <random>

#include <catch2/catch_test_macros.hpp>

#include "faest.h"
#include "lowmc_plain/lowmc.hpp"
#include "parameters.hpp"
#include "polynomials.hpp"
#include "rain_tower_tables.hpp"
#include "rainhash_plain/rain_hash.h"

using namespace faest;

namespace
{
std::mt19937_64 rng(0x4e494253);

void fill(uint8_t* p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        p[i] = uint8_t(rng());
}
} // namespace

TEST_CASE("LowMC is a keyed permutation at every level", "[lowmc]")
{
    nibs_lowmc_init();
    for (unsigned level : {1u, 3u, 5u})
    {
        const unsigned nb = nibs_lowmc_block_bytes(level);
        for (int trial = 0; trial < 50; ++trial)
        {
            uint8_t k[32], pt[32], ct[32], back[32], ct2[32];
            fill(k, nb);
            fill(pt, nb);
            nibs_lowmc_encrypt(level, k, pt, ct);
            nibs_lowmc_decrypt(level, k, ct, back);
            REQUIRE(std::memcmp(back, pt, nb) == 0); // D_K(E_K(x)) = x
            nibs_lowmc_decrypt(level, k, pt, back);
            nibs_lowmc_encrypt(level, k, back, ct2);
            REQUIRE(std::memcmp(ct2, pt, nb) == 0); // E_K(D_K(y)) = y
            REQUIRE(std::memcmp(ct, pt, nb) != 0);
        }
    }
}

// The level-3/5 lane embeddings must turn the plain Rain tower inverse into
// "in * out == 1" inside FAEST's own F_{2^192} / F_{2^256} arithmetic.
template <secpar S, size_t D>
static void check_tower(const std::array<const unsigned char (*)[S == secpar::s192 ? 24 : 32], D>& tabs)
{
    constexpr size_t BITS = secpar_to_bits(S);
    using F = poly_secpar<S>;
    auto mul = [](const F& a, const F& b) { return (a * b).template reduce_to<BITS>(); };
    auto emb = [&](const uint8_t* lane, size_t c)
    {
        F v = F::set_zero();
        for (size_t b = 0; b < 128; ++b)
            if ((lane[b / 8] >> (b % 8)) & 1)
                v += F::load_dup(tabs[c][b]);
        return v;
    };
    F c0 = F::set_zero(), c1 = F::set_zero();
    if constexpr (D == 2)
    {
        c0 = F::load_dup(RAIN_LANE_192_C0);
        c1 = F::load_dup(RAIN_LANE_192_C1);
    }
    using L = std::array<F, D>;
    auto lmul = [&](const L& x, const L& y)
    {
        L o;
        if constexpr (D == 1)
            o[0] = mul(x[0], y[0]);
        else
        {
            F bb = mul(x[1], y[1]);
            o[0] = mul(x[0], y[0]) + mul(c0, bb);
            o[1] = mul(x[0], y[1]) + mul(x[1], y[0]) + mul(c1, bb);
        }
        return o;
    };
    auto ladd = [](const L& x, const L& y)
    {
        L o;
        for (size_t c = 0; c < D; ++c)
            o[c] = x[c] + y[c];
        return o;
    };
    uint8_t a123[16] = {0};
    a123[123 / 8] = uint8_t(1u << (123 % 8));
    L k;
    for (size_t c = 0; c < D; ++c)
        k[c] = emb(a123, c);

    for (int trial = 0; trial < 20; ++trial)
    {
        uint8_t x[64], y[64];
        fill(x, 64);
        field::GF2_512 fx;
        fx.from_bytes(x);
        fx.inverse().to_bytes(y);

        L a[4], b[4];
        for (size_t i = 0; i < 4; ++i)
            for (size_t c = 0; c < D; ++c)
            {
                a[i][c] = emb(x + 16 * i, c);
                b[i][c] = emb(y + 16 * i, c);
            }
        L cc[7];
        bool set[7] = {false};
        for (size_t i = 0; i < 4; ++i)
            for (size_t j = 0; j < 4; ++j)
            {
                L p = lmul(a[i], b[j]);
                cc[i + j] = set[i + j] ? ladd(cc[i + j], p) : p;
                set[i + j] = true;
            }
        for (int t = 6; t >= 4; --t)
        {
            cc[t - 2] = ladd(cc[t - 2], lmul(cc[t], k));
            cc[t - 3] = ladd(cc[t - 3], cc[t]);
            cc[t - 4] = ladd(cc[t - 4], cc[t]);
        }
        for (size_t t = 0; t < 4; ++t)
            for (size_t c = 0; c < D; ++c)
            {
                F expect = (t == 0 && c == 0) ? F::load_dup(tabs[0][0]) : F::set_zero();
                REQUIRE(cc[t][c] == expect);
            }
    }
}

TEST_CASE("Rain tower embedding is multiplicative at levels 3 and 5", "[rain]")
{
    check_tower<secpar::s256, 1>({RAIN_LANE_EMB_256});
    check_tower<secpar::s192, 2>({RAIN_LANE_EMB_192_A, RAIN_LANE_EMB_192_B});
}

TEST_CASE("Level-1 target mode matches the original two-block derivation", "[target]")
{
    // Original layout (fields of M in NIBS order r || pkR):
    // B1 = r(16) || pkR(32) || salt[0:16]; h1 = Rain(B1);
    // B2 = (salt[16:24] || 0xff^56) xor h1; t = Rain(B2)[0:39].
    uint8_t msg[72], t[39], b1[64], h1[64], b2[64], h2[64];
    fill(msg, sizeof msg);
    nibs_target(1, msg, sizeof msg, t, sizeof t);
    std::memcpy(b1, msg, 64);
    rain_hash(b1, h1);
    std::memset(b2, 0xff, 64);
    std::memcpy(b2, msg + 64, 8);
    for (int i = 0; i < 64; ++i)
        b2[i] ^= h1[i];
    rain_hash(b2, h2);
    REQUIRE(std::memcmp(t, h2, sizeof t) == 0);
}
