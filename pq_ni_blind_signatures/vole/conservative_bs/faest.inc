#ifndef FAEST_INC
#define FAEST_INC

#include "faest.hpp"
#include "faest_keys.inc"

#include "parameters.hpp"
#include "hash.hpp"
#include "owf_proof.hpp"
#include "quicksilver.hpp"
#include "small_vole.hpp"
#include "transpose_secpar.hpp"
#include "util.hpp"
#include "vector_com.inc"
#include "vole_check.hpp"
#include "vole_commit.hpp"
#include <cassert>
#include <cstdalign>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include "test/fips202.h"
}

#include <memory>
#include "nibs_target.hpp"

namespace faest
{

// Inputs to a NIBS proof. Byte strings are in the layout of nibs_layout<S, O>.
struct nibs_prover_inputs
{
    const uint8_t* expanded_pk; // MAYO expanded public key (statement)
    const uint8_t* m_pub;       // public message m = LowMC_K(.) (statement)
    const uint8_t* s;           // MAYO preimage, encoded (without salt)
    const uint8_t* K;           // receiver LowMC key
    const uint8_t* op;          // BCGY commitment opening op, or sPRP randomness s
    const uint8_t* nonce;       // signer nonce r
    const uint8_t* salt;        // MAYO salt (ignored for One-More-MAYO)
};

// Fill the NIBS witness (nibs_layout<S, O>::WITNESS_BYTES) from the secrets.
template <typename P> void nibs_build_witness(const nibs_prover_inputs& in, uint8_t* w)
{
    constexpr auto S = P::secpar_v;
    using LAY = nibs_layout<S, P::owf_v>;
    constexpr unsigned LEVEL = nibs_level<S>::LEVEL;

    memset(w, 0, LAY::WITNESS_BYTES);
    memcpy(w + LAY::K_OFF / 8, in.K, LAY::K_BYTES);
    memcpy(w + LAY::R_OFF / 8, in.nonce, LAY::R_BYTES);
    memcpy(w + LAY::OP_OFF / 8, in.op, LAY::OP_BYTES);
    if constexpr (LAY::SPRP)
        w[LAY::OP_OFF / 8 + LAY::OP_BYTES - 1] &= 0x7f; // s: domain bit 0
    if constexpr (LAY::SALT_BYTES)
        memcpy(w + LAY::SALT_OFF / 8, in.salt, LAY::SALT_BYTES);

    uint8_t m[32];
    nibs_message(LEVEL, LAY::SPRP, in.K, in.nonce, m, w + LAY::LOWMC_M_OFF / 8);

    uint8_t pkr[64];
    if constexpr (LAY::SPRP)
        nibs_sprp_pkr(LEVEL, in.op, in.K, pkr, w + LAY::LOWMC_PK_OFF / 8);
    else
        nibs_bcgy_pkr(LEVEL, in.op, in.K, pkr, w + LAY::GADA_OFF / 8);

    uint8_t msg[LAY::T_MSG_BYTES];
    if constexpr (LAY::NONCE_FIRST)
    {
        memcpy(msg, in.nonce, LAY::R_BYTES);
        memcpy(msg + LAY::R_BYTES, pkr, LAY::PKR_BYTES);
    }
    else
    {
        memcpy(msg, pkr, LAY::PKR_BYTES);
        memcpy(msg + LAY::PKR_BYTES, in.nonce, LAY::R_BYTES);
    }
    if constexpr (LAY::SALT_BYTES)
        memcpy(msg + LAY::R_BYTES + LAY::PKR_BYTES, in.salt, LAY::SALT_BYTES);
    uint8_t t[LAY::T_BYTES];
    nibs_target_hash(LEVEL, msg, LAY::T_MSG_BYTES, t, LAY::T_BYTES, w + LAY::T_OFF / 8);
}

// Test helper: evaluate the circuit on the witness built from `in`, with bit
// `flip_bit` of the full witness (NIBS part || MAYO s) flipped (SIZE_MAX: no
// flip), and return how many constraints are unsatisfied. No VOLE
// correlations are involved; only the constraint values are checked.
template <typename P> size_t nibs_count_unsatisfied_t(const nibs_prover_inputs& in, size_t flip_bit)
{
    using CP = P::CONSTS;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> packed_sk(FAEST_SECRET_KEY_BYTES<P>);
    uint8_t* p = packed_sk.data();
    memcpy(p, in.expanded_pk, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>);
    p += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>;
    memcpy(p, in.m_pub, HASHED_MSG_SIZE_BYTES<S>);
    p += HASHED_MSG_SIZE_BYTES<S>;
    nibs_build_witness<P>(in, p);
    memcpy(p + NIBS_WITNESS_BYTES<P>, in.s, VOLEMAYO_S_BYTES<S>);
    if (flip_bit != SIZE_MAX)
    {
        if (flip_bit >= OC::WITNESS_BITS)
            return SIZE_MAX;
        p[flip_bit / 8] ^= uint8_t(1u << (flip_bit % 8));
    }

    auto sk = std::make_unique<faest::secret_key<P>>();
    faest_unpack_secret_key<P>(sk.get(), packed_sk.data());

    std::vector<uint8_t> wit(CP::QUICKSILVER_ROWS_PADDED / 8 + 64, 0);
    memcpy(wit.data(), &sk->witness[0], (OC::WITNESS_BITS + 7) / 8);
    auto* macs = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(
        alignof(faest::block_secpar<S>), CP::QUICKSILVER_ROWS_PADDED * sizeof(faest::block_secpar<S>)));
    memset(macs, 0, CP::QUICKSILVER_ROWS_PADDED * sizeof(faest::block_secpar<S>));
    std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2{};
    for (size_t i = 0; i < chal2.size(); ++i)
        chal2[i] = uint8_t(0x5a ^ i);

    faest::quicksilver_state<S, false, OC::QS_DEGREE> qs(wit.data(), macs, OC::OWF_NUM_CONSTRAINTS,
                                                        chal2.data());
    qs_soft_check = true;
    qs_dbg_fails = 0;
    faest::owf_constraints<P, false>(&qs, &sk->pk, chal2.data());
    qs_soft_check = false;
    free(macs);
    return qs_dbg_fails;
}

template <typename P>
bool vole_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len,
                const nibs_prover_inputs& in, const uint8_t* r_additional)
{
    using CP = P::CONSTS;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;

    // packed sk = expanded pk || m || NIBS witness || s ; packed pk = expanded pk || m
    std::vector<uint8_t> packed_sk(FAEST_SECRET_KEY_BYTES<P>);
    {
        uint8_t* p = packed_sk.data();
        memcpy(p, in.expanded_pk, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>);
        p += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>;
        memcpy(p, in.m_pub, HASHED_MSG_SIZE_BYTES<S>);
        p += HASHED_MSG_SIZE_BYTES<S>;
        nibs_build_witness<P>(in, p);
        p += NIBS_WITNESS_BYTES<P>;
        memcpy(p, in.s, VOLEMAYO_S_BYTES<S>);
    }

    // SHAKE hash state the we will keep reusing.
    faest::hash_state hasher;

    // (r, iv^pre) <- H_3(mu || r)
    faest::block_secpar<S> seed; // r
    block128 iv_pre;
    faest::block128 iv;
    std::array<uint8_t, sizeof(seed) + sizeof(iv)> seed_iv_pre;
    // Hedged seed (as in FAEST): (seed, iv_pre) <- H_3(witness || fs_context || rho).
    // rho must be fresh randomness; the witness term keeps distinct witnesses
    // from ever sharing VOLE randomness even if rho is reused.
    hasher.init(S);
    hasher.update(packed_sk.data() + FAEST_PUBLIC_KEY_BYTES<P>,
                  NIBS_WITNESS_BYTES<P> + VOLEMAYO_S_BYTES<S>);
    hasher.update(r_additional, 32);
    if (random_seed && random_seed_len)
        hasher.update(random_seed, random_seed_len);
    hasher.update_byte(3);
    hasher.finalize(seed_iv_pre.data(), sizeof(seed_iv_pre));
    memcpy(&seed, seed_iv_pre.data(), sizeof(seed));
    memcpy(&iv_pre, &seed_iv_pre[sizeof(seed)], sizeof(iv));

    // for (size_t i = 0; i < sizeof(iv); i++) {
    //     std::cout << "vole_prove_1 iv_pre 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(iv_pre)[i] << "\n";
    // }

    // iv <- H_4(iv^pre)
    hasher.init(S);
    hasher.update(&iv_pre, sizeof(iv));
    hasher.update_byte(4);
    hasher.finalize(reinterpret_cast<uint8_t*>(&iv), sizeof(iv));

    // std::cout << "vole_prove_1 iv 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(&iv)[0] << "\n";

    block_secpar<S>* forest = reinterpret_cast<block_secpar<S>*>(
        aligned_alloc(alignof(block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(
        alignof(block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    vole_block* u = reinterpret_cast<vole_block*>(
        aligned_alloc(alignof(vole_block), CP::VOLE_COL_BLOCKS * sizeof(vole_block)));
    vole_block* v = reinterpret_cast<vole_block*>(aligned_alloc(
        alignof(vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(vole_block)));    
    uint8_t vole_commit_check[CP::VOLE_COMMIT_CHECK_SIZE];

    vole_commit<P>(seed, iv, forest, hashed_leaves, u, v, proof, vole_commit_check);

    // std::cout << "vole_prove_1 vole_commit_check 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)vole_commit_check[0] << "\n";
    // std::cout << "vole_prove_1 proof 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)proof[0] << "\n";

    // Getting the additional r
    hasher.init(S);
    hasher.update(r_additional, 32);
    std::array<uint8_t, 32> r_additional_hash_out;
    hasher.finalize(r_additional_hash_out.data(), 32);

    // chall_1 <- H_2^1(mu || com || c_1 || ... || c_\tau-1 || iv)
    std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES> chal1;
    hasher.init(S);
    hasher.update(r_additional_hash_out.data(), 32);
    hasher.update(vole_commit_check, CP::VOLE_COMMIT_CHECK_SIZE);
    hasher.update(proof, CP::VOLE_COMMIT_SIZE);
    hasher.update(&iv, sizeof(iv));
    hasher.update_byte(8 + 1);
    std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES> out;
    hasher.finalize(out.data(), CP::VOLE_CHECK::CHALLENGE_BYTES);
    memcpy(chal1.data(), out.data(), CP::VOLE_CHECK::CHALLENGE_BYTES);      // getting the challenge
    
    auto sk_box = std::make_unique<faest::secret_key<P>>();
    faest::secret_key<P>& sk = *sk_box;
    if (!faest_unpack_secret_key<P>(&sk, packed_sk.data()))
        return false;

    // SHAKE hash state the we will keep reusing.
    // faest::hash_state hasher;

    // chall_2 <- H_2^2(chall_1 || \tilde{u} || h_V || d)
    std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2;
    hasher.init(S);
    hasher.update(r_additional, 32);
    assert(sizeof(chal1) == CP::VOLE_CHECK::CHALLENGE_BYTES);
    hasher.update(chal1.data(), CP::VOLE_CHECK::CHALLENGE_BYTES);

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - ((proof + faest::VOLE_PROOF_BYTES<P>) 
    //     - P::grinding_counter_size
    //     - sizeof(iv_pre)
    //     - sizeof(faest::block_secpar<S>)
    //     - P::bavc_t::OPEN_SIZE
    //     - CP::QS::PROOF_BYTES
    //     - (OC::WITNESS_BITS + 7) / 8
    //     - P::CONSTS::VOLE_CHECK::PROOF_BYTES) << "\n";

    FAEST_ASSERT(proof
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8
        - P::CONSTS::VOLE_CHECK::PROOF_BYTES
        - CP::VOLE_COMMIT_SIZE);


    uint8_t* vole_check_proof = proof + CP::VOLE_COMMIT_SIZE;

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - ((proof + faest::VOLE_PROOF_BYTES<P>) 
    //     - P::grinding_counter_size
    //     - sizeof(iv_pre)
    //     - sizeof(faest::block_secpar<S>)
    //     - P::bavc_t::OPEN_SIZE
    //     - CP::QS::PROOF_BYTES
    //     - (OC::WITNESS_BITS + 7) / 8
    //     - P::CONSTS::VOLE_CHECK::PROOF_BYTES) << "\n";
    
    FAEST_ASSERT(proof + CP::VOLE_COMMIT_SIZE
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8
        - P::CONSTS::VOLE_CHECK::PROOF_BYTES);

    // vole_check_sender hashes u_tilde and V_tilde
    vole_check_sender<P>(u, v, chal1.data(), vole_check_proof, hasher);

    uint8_t* correction = vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES;
    FAEST_ASSERT(vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8);

    size_t remainder = ((OC::WITNESS_BITS + 7) / 8) % (16 * CP::VOLE_BLOCK);
    for (size_t i = 0; i < CP::WITNESS_BLOCKS - (remainder != 0); ++i)
    {
        faest::vole_block correction_i = u[i] ^ sk.witness[i];
        memcpy(correction + i * sizeof(faest::vole_block), &correction_i, sizeof(faest::vole_block));
    }
    if (remainder)
    {
        faest::vole_block correction_i = u[CP::WITNESS_BLOCKS - 1] ^ sk.witness[CP::WITNESS_BLOCKS - 1];
        memcpy(correction + (CP::WITNESS_BLOCKS - 1) * sizeof(faest::vole_block), &correction_i,
               remainder);
    }

    // continue with H_2^2
    hasher.update(correction, (OC::WITNESS_BITS + 7) / 8);
    hasher.update_byte(8 + 2);
    hasher.finalize(chal2.data(), sizeof(chal2));

    // std::cout << "vole_prove_1 chal2 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal2[0] << std::endl;

    faest::block_secpar<S>* macs = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(
        alignof(faest::block_secpar<S>), CP::QUICKSILVER_ROWS_PADDED * sizeof(faest::block_secpar<S>)));

    memcpy(&u[0], &sk.witness[0], (OC::WITNESS_BITS + 7) / 8);
    static_assert(CP::QUICKSILVER_ROWS_PADDED % faest::TRANSPOSE_BITS_ROWS == 0, "");
    transpose_secpar<S>(v, macs, CP::VOLE_COL_STRIDE, CP::QUICKSILVER_ROWS_PADDED);
    free(v);

    faest::quicksilver_state<S, false, OC::QS_DEGREE> qs((uint8_t*)&u[0], macs, OC::OWF_NUM_CONSTRAINTS, chal2.data());

    faest::owf_constraints<P, false>(&qs, &sk.pk, chal2.data());

    uint8_t* qs_proof = correction + (OC::WITNESS_BITS + 7) / 8;
    FAEST_ASSERT(correction + (OC::WITNESS_BITS + 7) / 8
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES);

    std::array<uint8_t, CP::QS::CHECK_BYTES> qs_check;
    qs.prove(OC::WITNESS_BITS, qs_proof, qs_check.data());
    free(macs);
    free(u);

    uint8_t* veccom_open_start = qs_proof + CP::QS::PROOF_BYTES;
    FAEST_ASSERT(qs_proof + CP::QS::PROOF_BYTES 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE);

    uint8_t* delta = veccom_open_start + P::bavc_t::OPEN_SIZE;
    FAEST_ASSERT(veccom_open_start + P::bavc_t::OPEN_SIZE 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>));

    uint8_t* iv_pre_dst = delta + sizeof(faest::block_secpar<S>);
    FAEST_ASSERT(delta + sizeof(faest::block_secpar<S>) 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre));

    memcpy(iv_pre_dst, &iv_pre, sizeof(faest::block128));
    uint8_t* grinding_counter_dst = iv_pre_dst + sizeof(iv_pre);

    FAEST_ASSERT(iv_pre_dst + sizeof(iv_pre) 
    == proof + faest::VOLE_PROOF_BYTES<P> - P::grinding_counter_size);

    if constexpr (!P::use_grinding)
    {
        // chall_3 <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2)
        hasher.init(S);
        hasher.update(chal2.data(), sizeof(chal2));
        hasher.update(qs_check.data(), CP::QS::CHECK_BYTES);
        hasher.update(qs_proof, CP::QS::PROOF_BYTES);
        hasher.update_byte(8 + 3);
        hasher.finalize(delta, sizeof(faest::block_secpar<S>));

        std::array<uint8_t, P::delta_bits_v> delta_bytes;
        faest::expand_bits_to_bytes(delta_bytes.data(), P::delta_bits_v, delta);

        P::bavc_t::open(forest, hashed_leaves, delta_bytes.data(), veccom_open_start);
    }
    else
    {
        // chall_3 <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2 || ctr)
        // Initialize a 4x hasher and hash the common input prefix.
        faest::hash_state_x4 grinding_hasher;
        grinding_hasher.init(S);
        grinding_hasher.update_1(chal2.data(), sizeof(chal2));
        grinding_hasher.update_1(qs_check.data(), CP::QS::CHECK_BYTES);
        grinding_hasher.update_1(qs_proof, CP::QS::PROOF_BYTES);
        uint32_t counter;
        bool open_success = grind_and_open<typename P::bavc_t>(
            forest, hashed_leaves, delta, veccom_open_start, &grinding_hasher, &counter);
        // Opening fails with a negligible probability, so we can assume it succeeds.
        FAEST_ASSERT(open_success);
        if (!open_success) return false;
        // Store counter in the signature.
        grinding_counter_dst[0] = counter;
        grinding_counter_dst[1] = counter >> 8;
        grinding_counter_dst[2] = counter >> 16;
        grinding_counter_dst[3] = counter >> 24;
    }

    free(forest);
    free(hashed_leaves);

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - grinding_counter_dst + P::grinding_counter_size << "\n";
    FAEST_ASSERT(grinding_counter_dst + P::grinding_counter_size == proof + faest::VOLE_PROOF_BYTES<P>);

    return true;

}

template <typename P>
bool vole_verify(const uint8_t* proof, size_t proof_size, const uint8_t* expanded_pk,
                 const uint8_t* m_pub, const uint8_t* r_additional)
{
    using CP = P::CONSTS;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;
    if (proof_size != VOLE_PROOF_BYTES<P>)
        return false;

    // std::cout << "vole_verify!!! \n" << std::flush;
    
    // SHAKE hash state the we will keep reusing.
    faest::hash_state hasher;

    // mu <- H_2^0(pk || msg)
    // faest::block_2secpar<S> mu;
    // hasher.init(S);
    // hasher.update(packed_pk, packed_pk_size);
    // hasher.update(commit_mu, commit_mu_size);
    // hasher.update_byte(8 + 0);
    // hasher.finalize(&mu, sizeof(mu));

    faest::block128 iv;

    const uint8_t* vole_check_proof = proof + CP::VOLE_COMMIT_SIZE;
    const uint8_t* correction = vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES;
    const uint8_t* qs_proof = correction + OC::WITNESS_BITS / 8;
    const uint8_t* veccom_open_start = qs_proof + CP::QS::PROOF_BYTES;
    const uint8_t* delta = veccom_open_start + P::bavc_t::OPEN_SIZE;
    const uint8_t* iv_pre_ptr = delta + sizeof(faest::block_secpar<S>);
    const uint8_t* counter = iv_pre_ptr + sizeof(iv);

    // for (size_t i = 0; i < sizeof(iv); i++) {
    //     std::cout << "vole_verify iv_pre_ptr 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)iv_pre_ptr[i] << "\n";
    // }
    // std::cout << "vole_verify counter 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)counter[0] << "\n";

    // Check that the prover actually did its grinding.
    for (size_t i = secpar_to_bits(S) - 1; i >= CP::VEC_COM::delta_bits_v; --i)
        if ((delta[i / 8] >> (i % 8)) & 1)
            return false;

    // iv <- H_4(iv^pre)
    hasher.init(S);
    hasher.update(iv_pre_ptr, sizeof(iv));
    hasher.update_byte(4);
    hasher.finalize(reinterpret_cast<uint8_t*>(&iv), sizeof(iv));

    // std::cout << "vole_verify iv 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(&iv)[0] << "\n";

    std::array<uint8_t, P::delta_bits_v> delta_bytes;
    faest::expand_bits_to_bytes(delta_bytes.data(), P::delta_bits_v, delta);

    faest::vole_block* q = reinterpret_cast<faest::vole_block*>(aligned_alloc(
        alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    uint8_t vole_commit_check[CP::VOLE_COMMIT_CHECK_SIZE];

    if (!vole_reconstruct<P>(iv, q, delta_bytes.data(), proof, veccom_open_start,
                             vole_commit_check))
    {
        free(q);
        return false;
    }

    // std::cout << "vole_verify vole_commit_check 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)vole_commit_check[0] << "\n";
    // std::cout << "vole_verify proof 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)proof[0] << "\n";

    // Getting the additional r
    hasher.init(S);
    hasher.update(r_additional, 32);
    std::array<uint8_t, 32> r_additional_hash_out;
    hasher.finalize(r_additional_hash_out.data(), 32);

    // chall_1 <- H_2^1(mu || com || c_1 || ... || c_\tau-1 || iv)
    std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES> chal1;
    hasher.init(S);
    hasher.update(r_additional_hash_out.data(), 32);
    // hasher.update(&mu, sizeof(mu));
    hasher.update(vole_commit_check, CP::VOLE_COMMIT_CHECK_SIZE);
    hasher.update(proof, CP::VOLE_COMMIT_SIZE);
    hasher.update(&iv, sizeof(iv));
    hasher.update_byte(8 + 1);
    hasher.finalize(chal1.data(), sizeof(chal1));

    // std::cout << "vole_verify chal1 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal1[0] << std::endl;;

    // chall_2 <- H_2^2(chall_1 || \tilde{u} || h_V || d)
    std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2;
    hasher.init(S);
    hasher.update(r_additional, 32);
    hasher.update(chal1.data(), sizeof(chal1));
    hasher.update(vole_check_proof, CP::VOLE_CHECK::PROOF_BYTES);

    // vole_check_receiver hashes D
    vole_check_receiver<P>(q, delta_bytes.data(), chal1.data(), vole_check_proof, hasher);

    // continue with H_2^2
    hasher.update(correction, OC::WITNESS_BITS / 8);
    hasher.update_byte(8 + 2);
    hasher.finalize(chal2.data(), sizeof(chal2));

    // std::cout << "vole_verify chal2 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal2[0] << std::endl;;

    std::array<faest::vole_block, CP::WITNESS_BLOCKS> correction_blocks;
    memcpy(&correction_blocks, correction, OC::WITNESS_BITS / 8);
    memset(reinterpret_cast<uint8_t*>(correction_blocks.data()) + OC::WITNESS_BITS / 8, 0,
           sizeof(correction_blocks) - OC::WITNESS_BITS / 8);
    vole_receiver_apply_correction<P>(CP::WITNESS_BLOCKS, P::delta_bits_v, correction_blocks.data(), q,
                                      delta_bytes.data());

    faest::block_secpar<S>* macs = reinterpret_cast<faest::block_secpar<S>*>(
        aligned_alloc(alignof(faest::block_secpar<S>), CP::VOLE_ROWS_PADDED * sizeof(faest::block_secpar<S>)));
    transpose_secpar<S>(q, macs, CP::VOLE_COL_STRIDE, CP::QUICKSILVER_ROWS_PADDED);
    free(q);

    faest::block_secpar<S> delta_block;
    memcpy(&delta_block, delta, sizeof(delta_block));

    auto pk_box = std::make_unique<faest::public_key<P>>();
    faest::public_key<P>& pk = *pk_box;
    memset(&pk.msg[0], 0, sizeof(pk.msg));
    memcpy(pk.mayo_expanded_pk, expanded_pk, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>);
    memcpy(&pk.msg[0], m_pub, HASHED_MSG_SIZE_BYTES<S>);

    faest::quicksilver_state<S, true, OC::QS_DEGREE> qs(macs, OC::OWF_NUM_CONSTRAINTS, delta_block, chal2.data());

    faest::owf_constraints<P, true>(&qs, &pk, chal2.data());

    std::array<uint8_t, CP::QS::CHECK_BYTES> qs_check;
    qs.verify(OC::WITNESS_BITS, qs_proof, qs_check.data());
    free(macs);

    // chall_3' <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2 [|| ctr])
    faest::block_secpar<S> delta_check;
    hasher.init(S);
    hasher.update(chal2.data(), sizeof(chal2));
    hasher.update(qs_check.data(), CP::QS::CHECK_BYTES);
    hasher.update(qs_proof, CP::QS::PROOF_BYTES);
    if constexpr (P::use_grinding)
    {
        hasher.update(counter, P::grinding_counter_size);
    }
    hasher.update_byte(8 + 3);
    hasher.finalize(&delta_check, sizeof(delta_check));

    return memcmp(delta, &delta_check, sizeof(delta_check)) == 0;

}


} // namespace faest

#endif
