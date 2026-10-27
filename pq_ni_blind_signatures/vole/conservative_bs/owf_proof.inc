#ifndef OWF_PROOF_INC
#define OWF_PROOF_INC

#include "aes.hpp"
#include "hash.hpp"
#include "constants.hpp"
#include "faest_keys.hpp"
#include "owf_proof.hpp"
#include "owf_proof_tools.hpp"
#include "parameters.hpp"
#include "quicksilver.hpp"
#include "rainhash_plain/rain_hash.h"
#include "lowmc_plain/lowmc.hpp"
#include "rain_tower_tables.hpp"

#include <algorithm>
#include <array>
#include <vector>

namespace faest
{

#include "nibs_circuit.inc"

// Mayo stuff
static inline uint8_t _mul_gf16(uint8_t a, uint8_t b) {

    size_t c = 0;
    while (b) {
        if (b & 1) {
            c ^= a;
        }
        a <<= 1;
        b >>= 1;
    }

    for(size_t i = 7; i > 3; i--) {
        if ((c >> i) & 1) {
            c ^= VOLEMAYO_MOD << (i - 4);
        }
    }
    return (uint8_t)c;
}
template <typename P>
static inline void _apply_e_p(uint64_t* data, size_t number_of_vecs){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;
    static constexpr size_t elements_in_last_uint = m - (uint64s_per_vec - 1) * 16;

    uint64_t last_mask = (((uint64_t)1) << (elements_in_last_uint * 4)) - 1;
    if (elements_in_last_uint == 16) {
        last_mask = 0xffffffffffffffff;
    }

    uint32_t tail_multiples[16];
    for (size_t i = 0; i < 16; i++) {
        tail_multiples[i] = 0;
        for (size_t j = 0; j < 4; j++) {
            tail_multiples[i] ^= _mul_gf16(i, VOLEMAYO_F_TAIL<P::secpar_v>[j]) << (j * 4);
        }
    }

    for (size_t idx = 0; idx < number_of_vecs; idx++) {
        char top_nibble = data[(idx+1) * uint64s_per_vec - 1] >> (((m-1) % 16) * 4);
        
        // shift up by 4 bits
        for (size_t i = uint64s_per_vec - 1; i > 0; i--) {
            data[idx * uint64s_per_vec + i] = (data[idx * uint64s_per_vec + i] << 4) |
                                              (data[idx * uint64s_per_vec + i - 1] >> 60);
        }
        data[idx * uint64s_per_vec] <<= 4;
        data[(idx+1) * uint64s_per_vec - 1] &= last_mask;
        // reduction mod f(X)
        data[idx * uint64s_per_vec] ^= tail_multiples[top_nibble];
    }
}
template <typename P>
static void _combineP1_P2_P3(const unsigned char * in, uint64_t *out){
    size_t i,j;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t v = VOLEMAYO_V<P::secpar_v>;
    static constexpr size_t o = VOLEMAYO_O<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;

    const unsigned char* P1 = in;
    const unsigned char* P2 = in + v*(v+1)/2*uint64s_per_vec*sizeof(uint64_t);
    const unsigned char* P3 = P2 + v*o*uint64s_per_vec*sizeof(uint64_t);

    memset(out, 0, n * (n + 1) / 2 * uint64s_per_vec * sizeof(uint64_t));

    // load and mix P1 and P2
    for (i = 0; i < v; i++) {
        for (j = i; j < v; j++) {
            memcpy((void *) out , P1, m / 2);
            P1 += uint64s_per_vec * sizeof(uint64_t);
            out += uint64s_per_vec;
        }
        for (; j < n; j++) {
            memcpy((void *) out , P2, m / 2);
            P2 += uint64s_per_vec * sizeof(uint64_t);
            out += uint64s_per_vec;
        }
    }
    // load P3
    memcpy((void *) out , P3, o*(o+1)/2*uint64s_per_vec*sizeof(uint64_t));
}
template <typename P>
static void sample_random_embedding(std::vector<poly_secpar<P::secpar_v>> &embedding_table, unsigned char * chall2){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    constexpr secpar S = P::secpar_v;
    static constexpr size_t security_bits = secpar_to_bits(S);

    
    embedding_table.resize(m*16);

    unsigned char randomness[m*sizeof(poly_secpar<S>)];

    hash_state hasher;

    // mu <- H_2^0(pk || msg)
    hasher.init(S);
    hasher.update(chall2, secpar_to_bits(S) / 4); // hash 2*lambda bits of chall2
    hasher.finalize(randomness, m*sizeof(poly_secpar<S>));

    const unsigned char (*gf4_in_gf_secpar)[security_bits/8]; 
    if constexpr (security_bits == 128) {
        gf4_in_gf_secpar = gf4_in_gf128;
    } else if constexpr (security_bits == 192) {
        gf4_in_gf_secpar = gf4_in_gf192;
    } else if constexpr (security_bits == 256) {
        gf4_in_gf_secpar = gf4_in_gf256;
    }

    poly_secpar<S> x   = poly_secpar<S>::load_dup(gf4_in_gf_secpar[0]);
    poly_secpar<S> xx  = poly_secpar<S>::load_dup(gf4_in_gf_secpar[1]);
    poly_secpar<S> xxx = poly_secpar<S>::load_dup(gf4_in_gf_secpar[2]);

    for (size_t i = 0; i < m; i++) {
        embedding_table[i*16 + 0] = poly_secpar<S>::set_zero();
        embedding_table[i*16 + 1] = poly_secpar<S>::load_dup(randomness + i*sizeof(poly_secpar<S>));
        embedding_table[i*16 + 2] = (x   * embedding_table[i*16 + 1]).template reduce_to<security_bits>();
        embedding_table[i*16 + 4] = (xx  * embedding_table[i*16 + 1]).template reduce_to<security_bits>();
        embedding_table[i*16 + 8] = (xxx * embedding_table[i*16 + 1]).template reduce_to<security_bits>();

        embedding_table[i*16 + 3] = embedding_table[i*16 + 2] + embedding_table[i*16 + 1];
        
        embedding_table[i*16 + 5] = embedding_table[i*16 + 4] + embedding_table[i*16 + 1];
        embedding_table[i*16 + 6] = embedding_table[i*16 + 4] + embedding_table[i*16 + 2];
        embedding_table[i*16 + 7] = embedding_table[i*16 + 4] + embedding_table[i*16 + 3];

        embedding_table[i*16 + 9]  = embedding_table[i*16 + 8] + embedding_table[i*16 + 1];
        embedding_table[i*16 + 10] = embedding_table[i*16 + 8] + embedding_table[i*16 + 2];
        embedding_table[i*16 + 11] = embedding_table[i*16 + 8] + embedding_table[i*16 + 3];
        embedding_table[i*16 + 12] = embedding_table[i*16 + 8] + embedding_table[i*16 + 4];
        embedding_table[i*16 + 13] = embedding_table[i*16 + 8] + embedding_table[i*16 + 5];
        embedding_table[i*16 + 14] = embedding_table[i*16 + 8] + embedding_table[i*16 + 6];
        embedding_table[i*16 + 15] = embedding_table[i*16 + 8] + embedding_table[i*16 + 7];
    }
}
template <typename P>
static void embed_gf16_vec(const std::vector<poly_secpar<P::secpar_v>>& embedding_table, const uint8_t* vec, poly_secpar<P::secpar_v> &poly){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;

    poly = poly_secpar<P::secpar_v>::set_zero();
    for (size_t i = 0; i < m; i+=2)
    {
        unsigned char nibble_low = vec[i/2] & 0xf;
        unsigned char nibble_high = (vec[i/2] >> 4) & 0xf;
        poly += embedding_table[i * 16 + nibble_low];
        poly += embedding_table[(i+1) * 16 + nibble_high];
    }
}

// MAYO verification T*(s) = t, batched into a single constraint with a random
// embedding of the m equations (Baum et al., USENIX'26, Sec. 8).
// t: m GF(16) wires (lifted to GF(2^lambda)); s read from the witness at s_off.
template <typename QS, typename P, owf O>
static void enc_constraints_mayo(QS* qs_state, const public_key<P>* pk, unsigned char* chal2,
                                 const std::vector<quicksilver_gfsecpar<QS, 1>>& t, size_t s_off)
{
    constexpr secpar S = QS::secpar_v;

    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t k = VOLEMAYO_K<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = VOLEMAYO_u64s_per_m_vec<S>;
    FAEST_ASSERT(t.size() == m);

    std::vector<poly_secpar<S>> embedding_table;
    sample_random_embedding<P>(embedding_table, chal2);

    quicksilver_gfsecpar<QS, 1> t_embedded(0, qs_state);
    for (size_t i = 0; i < m; i++)
        t_embedded += embedding_table[16 * i + 1] * t[i];

    size_t off = s_off;
    constexpr size_t s_elem_size = k * n;
    std::vector<quicksilver_gfsecpar<QS, 1>> s(s_elem_size);
    for (size_t idx = 0; idx < s_elem_size; idx++)
    {
        s[idx] = qs_state->load_witness_4_bits_and_combine(off);
        off += 4;
    }

    quicksilver_gfsecpar<QS, 2> u(0, qs_state);
    poly_secpar<S> embedded_column;

    std::vector<uint64_t> _expanded_pk(VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>);
    uint64_t* expanded_pk = _expanded_pk.data();
    _combineP1_P2_P3<P>((unsigned char*)pk->mayo_expanded_pk, expanded_pk);

    std::vector<quicksilver_gfsecpar<QS, 1>> As(n);
    for (int i = 0; i < (int)k; i++)
    {
        for (int j = (int)k - 1; j >= i; j--)
        {
            if (i != 0 || j != (int)k - 1)
                _apply_e_p<P>(expanded_pk, n * (n + 1) / 2);

            for (size_t a = 0; a < n; a++)
                As[a] = quicksilver_gfsecpar<QS, 1>(0, qs_state);

            // As = A * s_j (i == j) or (A + A^t) * s_j (i != j)
            size_t ctr = 0;
            for (size_t a = 0; a < n; a++)
            {
                ctr += (i != j);
                for (size_t b = a + (i != j); b < n; b++)
                {
                    embed_gf16_vec<P>(embedding_table, (unsigned char*)&expanded_pk[(ctr++) * uint64s_per_vec],
                                      embedded_column);
                    As[a] += embedded_column * s[j * n + b];
                    if (i != j)
                        As[b] += embedded_column * s[j * n + a];
                }
            }
            for (size_t a = 0; a < n; a++)
                u += As[a] * s[i * n + a];
        }
    }
    qs_state->add_constraint(u + t_embedded);
}

// The full NIBS relation R((vk, m), (presig = s_M || salt, r, K, op/s)).
template <typename QS, typename P, owf O>
static void enc_constraints(QS* qs, const public_key<P>* pk, unsigned char* chall2)
{
    constexpr secpar S = QS::secpar_v;
    using LAY = nibs_layout<S, O>;
    constexpr unsigned LEVEL = nibs_level<S>::LEVEL;
    constexpr size_t N = LAY::LAMBDA;

    const nibs_wires<QS> K = nibs_witness_wires(qs, LAY::K_OFF, N);
    const nibs_wires<QS> r = nibs_witness_wires(qs, LAY::R_OFF, N);

    // m = LowMC_K(r)  (BCGY)   or   m = LowMC_K(1 || r[0:N-1])  (sPRP)
    qs_dbg_region = "lowmc_m";
    nibs_wires<QS> pt = r;
    if constexpr (LAY::SPRP)
        pt[N - 1] = nibs_const_wire(qs, 1);
    nibs_wires<QS> m = nibs_lowmc_gadget<QS, LEVEL>(qs, K, pt, LAY::LOWMC_M_OFF);
    nibs_assert_bits_equal_const(qs, m.data(), (const uint8_t*)&pk->msg[0], N);

    // pk_R
    nibs_wires<QS> pkr;
    if constexpr (LAY::SPRP)
    {
        // pk_R = LowMC_K(0 || s): the witness slot holds s with its top bit,
        // the domain bit, constrained to 0 (Algorithm 1, KeyGen_R).
        qs_dbg_region = "lowmc_pk";
        const nibs_wires<QS> s = nibs_witness_wires(qs, LAY::OP_OFF, N);
        const uint8_t zero = 0;
        nibs_assert_bits_equal_const(qs, &s[N - 1], &zero, 1);
        pkr = nibs_lowmc_gadget<QS, LEVEL>(qs, K, s, LAY::LOWMC_PK_OFF);
    }
    else
    {
        qs_dbg_region = "rain_pk";
        nibs_wires<QS> in(VOLERAINHASH_B, nibs_const_wire(qs, 1));
        const nibs_wires<QS> op = nibs_witness_wires(qs, LAY::OP_OFF, 8 * LAY::OP_BYTES);
        for (size_t i = 0; i < op.size(); ++i)
            in[i] = op[i];
        for (size_t i = 0; i < N; ++i)
            in[op.size() + i] = K[i];
        nibs_wires<QS> c = nibs_rain_gadget(qs, in, LAY::GADA_OFF);
        pkr.assign(c.begin(), c.begin() + 8 * LAY::PKR_BYTES);
    }

    // t = T(M || salt) with M = r || pk_R. The signer's nonce lies in the
    // first Rain block, so no chaining value of T can be precomputed before
    // the nonce is known (see nibs_layout.hpp).
    qs_dbg_region = "rain_target";
    nibs_wires<QS> msg = r;
    msg.insert(msg.end(), pkr.begin(), pkr.end());
    const nibs_wires<QS> salt = nibs_witness_wires(qs, LAY::SALT_OFF, 8 * LAY::SALT_BYTES);
    msg.insert(msg.end(), salt.begin(), salt.end());
    const nibs_wires<QS> tbits = nibs_target_wires<QS, LAY>(qs, msg);

    constexpr size_t mm = VOLEMAYO_M<S>;
    std::vector<quicksilver_gfsecpar<QS, 1>> t(mm);
    for (size_t i = 0; i < mm; ++i)
        t[i] = quicksilver_gfsecpar<QS, 1>::combine_4_bits(&tbits[4 * i]);

    qs_dbg_region = "mayo";
    enc_constraints_mayo<QS, P, O>(qs, pk, chall2, t, LAY::S_OFF);
}

template <typename P, bool verifier>
void owf_constraints(quicksilver_state<P::secpar_v, verifier, P::OWF_CONSTS::QS_DEGREE>* state,
                     const public_key<P>* pk, unsigned char* chall2)
{
    using QS = quicksilver_state<P::secpar_v, verifier, P::OWF_CONSTS::QS_DEGREE>;
    constexpr auto O = P::owf_v;

    qs_dbg_idx = 0;
    enc_constraints<QS, P, O>(state, pk, chall2);
#ifdef QS_DEBUG_CONSTRAINTS
    if constexpr (!verifier)
        fprintf(stderr, "constraints emitted: %zu (declared: %zu)\n", qs_dbg_idx,
                (size_t)P::OWF_CONSTS::OWF_NUM_CONSTRAINTS);
#endif
    if constexpr (!verifier)
        FAEST_ASSERT(qs_dbg_idx == P::OWF_CONSTS::OWF_NUM_CONSTRAINTS);
}

} // namespace faest

#endif
