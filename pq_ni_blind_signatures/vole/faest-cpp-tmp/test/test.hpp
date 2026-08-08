#ifndef TEST_TEST_HPP
#define TEST_TEST_HPP

#include "constants.hpp"
#include "debug.hpp"
#include "faest_keys.inc"
#include "polynomials.hpp"
#include "quicksilver.hpp"

#include "../rainhash_plain/rain_hash.h"
#include "../lowmc_plain/lowmc.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace faest;

// Some of the test code still uses POLY_VEC_LEN
constexpr std::size_t POLY_VEC_LEN_SHIFT = 0;
constexpr std::size_t POLY_VEC_LEN = 1 << POLY_VEC_LEN_SHIFT;

struct secpar128_t
{
    constexpr static secpar value = secpar::s128;
};
struct secpar192_t
{
    constexpr static secpar value = secpar::s192;
};
struct secpar256_t
{
    constexpr static secpar value = secpar::s256;
};

#define REQUIRE_POLYVEC_EQ(a, b)                                                                   \
    {                                                                                              \
        INFO("Requiring: " << poly_to_string(a) << " == " << poly_to_string(b));                   \
        REQUIRE(a == b);                                                                           \
    }
#define REQUIRE_POLYVEC_NEQ(a, b)                                                                  \
    {                                                                                              \
        INFO("Requiring: " << poly_to_string(a) << " != " << poly_to_string(b));                   \
        REQUIRE(a != b);                                                                           \
    }

inline std::ostream& operator<<(std::ostream& o, const std::vector<uint8_t>& array)
{
    o << "{ ";
    for (size_t i = 0; i < array.size(); ++i)
    {
        if (i)
            o << ", ";
        o << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)array[i];
    }
    return o << " }";
}

template <size_t N>
inline std::ostream& operator<<(std::ostream& o, const std::array<uint8_t, N>& array)
{
    return o << std::vector(array.begin(), array.end());
}

template <typename T> inline T rand()
{
    static std::mt19937_64 rd(42);
    std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
    return dist(rd);
}

template <> inline block128 rand<block128>()
{
    std::array<uint64_t, 2> data;
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = rand<uint64_t>();

    block128 output;
    memcpy(&output, &data[0], sizeof(output));
    return output;
}

template <> inline block192 rand<block192>()
{
    std::array<uint64_t, 3> data;
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = rand();

    block192 output;
    memcpy(&output, &data[0], sizeof(output));
    return output;
}

template <> inline block256 rand<block256>()
{
    std::array<uint64_t, 4> data;
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = rand();

    block256 output;
    memcpy(&output, &data[0], sizeof(output));
    return output;
}

template <typename T> inline std::vector<T> random_vector(std::size_t size)
{
    std::vector<T> v(size);
    std::generate(v.begin(), v.end(), rand<T>);
    return v;
}

template <secpar S>
std::pair<std::vector<block_secpar<S>>, std::vector<block_secpar<S>>> inline gen_vole_correlation(
    size_t n, const uint8_t* witness, block_secpar<S> delta)
{
    const auto keys = random_vector<block_secpar<S>>(n);
    auto tags = keys;
    for (size_t i = 0; i < n; ++i)
    {
        if ((witness[i / 8] >> (i % 8)) & 1)
        {
            tags[i] = tags[i] ^ delta;
        }
    }
    return std::make_pair(keys, tags);
}

template <secpar S, size_t max_deg> struct quicksilver_test_state_pre_quicksilver
{
    using QS_CONS = QS_CONSTANTS<S, max_deg>;

    std::vector<uint8_t> witness;
    std::vector<block_secpar<S>> tags;
    std::vector<block_secpar<S>> keys;
    std::array<uint8_t, QS_CONS::CHALLENGE_BYTES> challenge;

    quicksilver_test_state_pre_quicksilver(const uint8_t* witness_in, size_t witness_bits,
                                           block_secpar<S> delta)
        : witness(witness_in, witness_in + witness_bits / 8)
    {
        auto witness_mask = random_vector<uint8_t>((max_deg - 1) * secpar_to_bytes(S));
        witness.insert(witness.end(), witness_mask.begin(), witness_mask.end());

        auto correlation = gen_vole_correlation<S>(witness_bits + (max_deg - 1) * secpar_to_bits(S),
                                                   witness.data(), delta);
        keys = std::move(correlation.first);
        tags = std::move(correlation.second);

        std::generate(challenge.begin(), challenge.end(), rand<uint8_t>);
    }
};

template <secpar S, size_t max_deg = 2>
struct quicksilver_test_state : public quicksilver_test_state_pre_quicksilver<S, max_deg>
{
    using base = quicksilver_test_state_pre_quicksilver<S, max_deg>;
    using QS_CONS = base::QS_CONS;
    using QSP = quicksilver_state<S, false, max_deg>;
    using QSV = quicksilver_state<S, true, max_deg>;

    QSP prover_state;
    QSV verifier_state;

    quicksilver_test_state(size_t num_constraints, const uint8_t* witness_in, size_t witness_bits,
                           block_secpar<S> delta)
        : base(witness_in, witness_bits, delta),
          prover_state(this->witness.data(), this->tags.data(), num_constraints,
                       this->challenge.data()),
          verifier_state(this->keys.data(), num_constraints, delta, this->challenge.data())
    {
    }

    template <size_t deg>
        requires(deg <= QSP::max_degree)
    bool check_mac(const quicksilver_gf2<QSP, deg>& x_p, const quicksilver_gf2<QSV, deg>& x_v) const
    {
        auto z = poly_secpar<S>::from_1(x_p.value());
        const auto delta = verifier_state.delta();
        for (size_t i = 1; i <= deg; ++i)
        {
            z = (z * delta).template reduce_to<secpar_to_bits(S)>();
            z += x_p.mac.coeffs[deg - i];
        }

        return z == x_v.mac;
    }

    template <size_t deg>
        requires(deg <= QSP::max_degree)
    bool check_mac(const quicksilver_gfsecpar<QSP, deg>& x_p,
                   const quicksilver_gfsecpar<QSV, deg>& x_v) const
    {
        auto z = x_p.value();
        const auto delta = verifier_state.delta();
        for (size_t i = 1; i <= deg; ++i)
        {
            z = (z * delta).template reduce_to<secpar_to_bits(S)>();
            z += x_p.mac.coeffs[deg - i];
        }

        return z == x_v.mac;
    }

    std::array<std::array<uint8_t, QS_CONS::CHECK_BYTES>, 2> compute_check() const
    {
        std::array<uint8_t, QS_CONS::PROOF_BYTES> proof;
        std::array<uint8_t, QS_CONS::CHECK_BYTES> check_prover, check_verifier;

        size_t witness_bits = 8 * this->witness.size() - (max_deg - 1) * secpar_to_bits(S);
        prover_state.prove(witness_bits, proof.data(), check_prover.data());
        verifier_state.verify(witness_bits, proof.data(), check_verifier.data());

        return {check_prover, check_verifier};
    }
};

// --- START ---

// reuding with the reduction poly in F_2^4
inline uint8_t mod_reduce(size_t a) {

    size_t c = a;
    for(size_t i = 7; i > 3; i--) {
        if ((c >> i) & 1) {
            c ^= VOLEMAYO_MOD << (i - 4);
        }
    }
    return (uint8_t)c;
}

// carry less mult
inline uint8_t mul_mod(uint8_t a, uint8_t b) {

    size_t c = 0;
    while (b) {
        if (b & 1) {
            c ^= a;
        }
        a <<= 1;
        b >>= 1;
    }

    return mod_reduce(c);

}

inline void memset_rand_mayo(unsigned char* in, size_t byte_size) {
    for (size_t i = 0; i < byte_size; i++) {
        memset(in + i, mod_reduce(rand()), 1);     // because 1 byte contains 2 elements in mod 16
    }
}

inline void memset_rand(unsigned char* in, size_t byte_size) {
    for (size_t i = 0; i < byte_size; i++) {
        memset(in + i, rand(), 1);     // because 1 byte contains 2 elements in mod 16
    }
}

template <typename P> inline void set_pk(unsigned char* pk) {



        size_t pk_offset = 0;

        pk_offset += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;
        // The mayo pk
        // NOTE: Setting the msg of lambda length
        memset_rand(pk + pk_offset, HASHED_MSG_SIZE_BYTES<P::secpar_v>);     
        pk_offset += HASHED_MSG_SIZE_BYTES<P::secpar_v>; 

        // The rain pk
        // set_fake_params();
        // NOTE: Stored coloumn major!!
        memcpy(pk + pk_offset, (uint8_t*)rain_roundconst.data(), VOLERAINHASH_RC_SIZE_BYTES);
        pk_offset += VOLERAINHASH_RC_SIZE_BYTES; 
        memcpy(pk + pk_offset, (uint8_t*)rain_matrix.data(), VOLERAINHASH_MAT_SIZE_BYTES);


}

template <typename P> inline void set_sk(uint8_t* sk, uint8_t* witness, uint8_t* pk,  uint8_t* s) {


        // copying all the mayo pk stuff to sk
        memcpy(sk, pk, VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
        size_t offset = VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;

        // the rain pk
        memcpy(sk + offset, pk + offset, VOLERAINHASH_PUBLIC_SIZE_BYTES);
        offset += VOLERAINHASH_PUBLIC_SIZE_BYTES;

        // NOTE: First rainhash happens, so store rainhash first after pk
        memcpy(sk + offset, witness, VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>);
        offset += VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>;

        // NOTE: storing the mayo sk
        memcpy(sk + offset, s, VOLEMAYO_S_BYTES<P::secpar_v>);

}


// NOTE: For the combined BS conservative implementation with mayo cons + keccak BS,,,
// Mayo has only s and the output of keccak (also the mayo output) as sk. 
// pk is just the matrices Ps
// Keccak part has no pk, the sk is the input, output and intermediate witness
template <typename P> inline void test_gen_keypair(unsigned char* pk, unsigned char* sk)
{
    

        set_pk<P>(pk);

        std::array<uint8_t, VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>> witness;
        memset(witness.data(), 0x00, VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>);

        // random recipient key material + nonce (the witness inputs)
        uint8_t K     [NIBS_K_BYTES];     memset_rand(K,      NIBS_K_BYTES);
        uint8_t open_r[NIBS_OP_BYTES];    memset_rand(open_r, NIBS_OP_BYTES);
        uint8_t nonce [NIBS_R_BYTES];     memset_rand(nonce,  NIBS_R_BYTES);
        uint8_t salt [VOLEMAYO_SALT_BYTES<P::secpar_v>];
        memset_rand(salt, VOLEMAYO_SALT_BYTES<P::secpar_v>);

        // LowMC init
        uint8_t m_pub[NIBS_M_BYTES];
        nibs_lowmc_init();
        nibs_lowmc_witness_expand(K, nonce, witness.data(), m_pub);

        // GadA
        uint8_t* ga = witness.data() + NIBS_GADA_IN_OFF / 8;
        memset(ga, 0xff, VOLERAINHASH_B_BYTES);
        memcpy(ga, open_r, NIBS_OP_BYTES);
        memcpy(ga + NIBS_OP_BYTES, K, NIBS_K_BYTES);
        rain_hash_with_sbox_output(ga, ga + VOLERAINHASH_B_BYTES,
                                   witness.data() + NIBS_GADA_OUT_OFF / 8);

        // Gad2 block 1
        uint8_t* b1 = witness.data() + NIBS_GAD2_B1_BIT_OFF / 8;
        memcpy(b1, witness.data() + NIBS_GADA_OUT_OFF / 8, NIBS_PKR_BYTES);
        memcpy(b1 + NIBS_PKR_BYTES, nonce, NIBS_R_BYTES);
        memcpy(b1 + NIBS_PKR_BYTES + NIBS_R_BYTES, salt, 16);
        rain_hash_with_sbox_output(b1, b1 + VOLERAINHASH_B_BYTES,
                                   witness.data() + NIBS_GAD2_H1_OFF / 8);

        // Gad2 block 2
        const uint8_t* h1 = witness.data() + NIBS_GAD2_H1_OFF / 8;
        uint8_t* b2 = witness.data() + NIBS_GAD2_B2_BIT_OFF / 8;
        memset(b2, 0xff, VOLERAINHASH_B_BYTES);
        memcpy(b2, salt + 16, VOLEMAYO_SALT_BYTES<P::secpar_v> - 16);
        for (size_t i = 0; i < VOLERAINHASH_B_BYTES; i++) b2[i] ^= h1[i];
        rain_hash_with_sbox_output(b2, b2 + VOLERAINHASH_B_BYTES,
                                   witness.data() + NIBS_GADGET_2_OUT_OFF / 8);

        // random s (MAYO preimage) -- the test's MAYO constraints check T*(s)=t
        std::array<uint8_t, VOLEMAYO_S_BYTES<P::secpar_v>> s;
        memset_rand((uint8_t*)&s, VOLEMAYO_S_BYTES<P::secpar_v>);

        // publish m = LowMC_K(r) into the pk slot for the GadM public constraint
        memcpy(pk + VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>,
               m_pub, NIBS_M_BYTES);

        set_sk<P>(sk, witness.data(), pk, (uint8_t*)&s);
      
}

// --- END ---

#endif
