// C entry points for the NIBS VOLEitH proofs and the cleartext helpers.
//
// One shared library serves every instance: 2 frameworks x 3 NIST levels x
// {s, f} x {v1, v2}. Instances are selected at run time by
// (variant, level, speed, version); see faest.h.

#include "faest.h"
#include "faest.inc"

#include <memory>

namespace faest
{
namespace
{

using prove_fn = bool (*)(uint8_t*, const uint8_t*, size_t, const nibs_prover_inputs&,
                          const uint8_t*);
using verify_fn = bool (*)(const uint8_t*, size_t, const uint8_t*, const uint8_t*,
                           const uint8_t*);
using info_fn = void (*)(nibs_instance_info*);
using check_fn = size_t (*)(const nibs_prover_inputs&, size_t);

template <typename P> void info_t(nibs_instance_info* o)
{
    constexpr auto S = P::secpar_v;
    using LAY = nibs_layout<S, P::owf_v>;
    o->proof_bytes = VOLE_PROOF_BYTES<P>;
    o->random_seed_bytes = P::secpar_bytes;
    o->witness_bits = P::OWF_CONSTS::WITNESS_BITS;
    o->nibs_witness_bits = LAY::WITNESS_BITS;
    o->mayo_s_bits = VOLEMAYO_S_BITS<S>;
    o->constraints = P::OWF_CONSTS::OWF_NUM_CONSTRAINTS;
    o->tau = P::tau_v;
    o->k_bytes = LAY::K_BYTES;
    o->r_bytes = LAY::R_BYTES;
    o->op_bytes = LAY::OP_BYTES;
    o->salt_bytes = LAY::SALT_BYTES;
    o->pkr_bytes = LAY::PKR_BYTES;
    o->m_bytes = LAY::M_BYTES;
    o->t_bytes = LAY::T_BYTES;
    o->s_bytes = VOLEMAYO_S_BYTES<S>;
    o->expanded_pk_bytes = VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>;
    o->lowmc_gadgets = LAY::LOWMC_GADGETS;
    o->rain_gadgets = LAY::RAIN_GADGETS;
    o->target_blocks = LAY::T_BLOCKS;
}

struct entry
{
    unsigned variant, level, speed, version;
    prove_fn prove;
    verify_fn verify;
    info_fn info;
    check_fn check;
};

// clang-format off
#define NIBS_ROW(V, L, SP, VER, P) entry{V, L, SP, VER, &vole_prove<P>, &vole_verify<P>, &info_t<P>, &nibs_count_unsatisfied_t<P>},
#define NIBS_ROWS(V, O)                                                                       \
    NIBS_ROW(V, 1, 0, 1, v1::nibs_128_s<O>) NIBS_ROW(V, 1, 1, 1, v1::nibs_128_f<O>)          \
    NIBS_ROW(V, 3, 0, 1, v1::nibs_192_s<O>) NIBS_ROW(V, 3, 1, 1, v1::nibs_192_f<O>)          \
    NIBS_ROW(V, 5, 0, 1, v1::nibs_256_s<O>) NIBS_ROW(V, 5, 1, 1, v1::nibs_256_f<O>)          \
    NIBS_ROW(V, 1, 0, 2, v2::nibs_128_s<O>) NIBS_ROW(V, 1, 1, 2, v2::nibs_128_f<O>)          \
    NIBS_ROW(V, 3, 0, 2, v2::nibs_192_s<O>) NIBS_ROW(V, 3, 1, 2, v2::nibs_192_f<O>)          \
    NIBS_ROW(V, 5, 0, 2, v2::nibs_256_s<O>) NIBS_ROW(V, 5, 1, 2, v2::nibs_256_f<O>)

const entry TABLE[] = {
    NIBS_ROWS(NIBS_VARIANT_BCGY, owf::nibs_bcgy)
    NIBS_ROWS(NIBS_VARIANT_SPRP, owf::nibs_sprp)
};
// clang-format on

const entry* lookup(unsigned variant, unsigned level, unsigned speed, unsigned version)
{
    for (const auto& e : TABLE)
        if (e.variant == variant && e.level == level && e.speed == speed && e.version == version)
            return &e;
    return nullptr;
}

bool is_sprp(unsigned variant)
{
    return variant == NIBS_VARIANT_SPRP;
}

} // namespace
} // namespace faest

using namespace faest;

extern "C" {

bool nibs_instance_info_get(unsigned variant, unsigned level, unsigned speed, unsigned version,
                            nibs_instance_info* out)
{
    const entry* e = lookup(variant, level, speed, version);
    if (!e || !out)
        return false;
    e->info(out);
    return true;
}

bool nibs_prove(unsigned variant, unsigned level, unsigned speed, unsigned version, uint8_t* proof,
                size_t proof_len, const uint8_t* random_seed, size_t random_seed_len,
                const uint8_t* expanded_pk, const uint8_t* m_pub, const uint8_t* s,
                const uint8_t* K, const uint8_t* op, const uint8_t* nonce, const uint8_t* salt,
                const uint8_t* fs_context)
{
    const entry* e = lookup(variant, level, speed, version);
    if (!e)
        return false;
    nibs_instance_info info;
    e->info(&info);
    if (proof_len != info.proof_bytes)
        return false;
    const nibs_prover_inputs in{expanded_pk, m_pub, s, K, op, nonce, salt};
    return e->prove(proof, random_seed, random_seed_len, in, fs_context);
}

bool nibs_verify(unsigned variant, unsigned level, unsigned speed, unsigned version,
                 const uint8_t* proof, size_t proof_len, const uint8_t* expanded_pk,
                 const uint8_t* m_pub, const uint8_t* fs_context)
{
    const entry* e = lookup(variant, level, speed, version);
    if (!e)
        return false;
    return e->verify(proof, proof_len, expanded_pk, m_pub, fs_context);
}

size_t nibs_count_unsatisfied(unsigned variant, unsigned level, unsigned speed, unsigned version,
                              const uint8_t* expanded_pk, const uint8_t* m_pub, const uint8_t* s,
                              const uint8_t* K, const uint8_t* op, const uint8_t* nonce,
                              const uint8_t* salt, size_t flip_bit)
{
    const entry* e = lookup(variant, level, speed, version);
    if (!e)
        return SIZE_MAX;
    const nibs_prover_inputs in{expanded_pk, m_pub, s, K, op, nonce, salt};
    return e->check(in, flip_bit);
}

void nibs_derive_pkr(unsigned variant, unsigned level, const uint8_t* K, const uint8_t* op,
                     uint8_t* pkr)
{
    if (is_sprp(variant))
        nibs_sprp_pkr(level, op, K, pkr, nullptr);
    else
        nibs_bcgy_pkr(level, op, K, pkr, nullptr);
}

void nibs_derive_message(unsigned variant, unsigned level, const uint8_t* K, const uint8_t* r,
                         uint8_t* m)
{
    nibs_message(level, is_sprp(variant), K, r, m, nullptr);
}

void nibs_target(unsigned level, const uint8_t* msg, size_t msg_len, uint8_t* t, size_t t_len)
{
    nibs_target_hash(level, msg, msg_len, t, t_len, nullptr);
}

void rain_hash_512_7_c(uint8_t* output, size_t outlen, const uint8_t* input, size_t inlen)
{
    assert(inlen == 64 && outlen <= 64);
    (void)inlen;
    uint8_t out[64];
    rain_hash(input, out);
    memcpy(output, out, outlen);
}

} // extern "C"
