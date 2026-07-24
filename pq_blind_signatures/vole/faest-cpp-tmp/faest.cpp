#include "faest.inc"

// VOLE STUFF
#include "../parameters.hpp"
#include <memory>

namespace faest
{

    // clang-format off

#if defined WITH_KECCAK
// ----- v1 -----
template bool faest_unpack_secret_key(secret_key<v1::keccak_then_mayo_128_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::keccak_then_mayo_128_f>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::keccak_then_mayo_192_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::keccak_then_mayo_192_f>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::keccak_then_mayo_256_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::keccak_then_mayo_256_f>*, const uint8_t*);

template void faest_pack_public_key(uint8_t*, const public_key<v1::keccak_then_mayo_128_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::keccak_then_mayo_128_f>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::keccak_then_mayo_192_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::keccak_then_mayo_192_f>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::keccak_then_mayo_256_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::keccak_then_mayo_256_f>*);

template void faest_unpack_public_key(public_key<v1::keccak_then_mayo_128_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::keccak_then_mayo_128_f>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::keccak_then_mayo_192_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::keccak_then_mayo_192_f>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::keccak_then_mayo_256_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::keccak_then_mayo_256_f>*, const uint8_t*);

template bool faest_pubkey<v1::keccak_then_mayo_128_s>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v1::keccak_then_mayo_128_f>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v1::keccak_then_mayo_192_s>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v1::keccak_then_mayo_192_f>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v1::keccak_then_mayo_256_s>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v1::keccak_then_mayo_256_f>(uint8_t*, const uint8_t*);

// ----- v2 -----
template bool faest_unpack_secret_key(secret_key<v2::keccak_then_mayo_128_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::keccak_then_mayo_128_f>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::keccak_then_mayo_192_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::keccak_then_mayo_192_f>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::keccak_then_mayo_256_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::keccak_then_mayo_256_f>*, const uint8_t*);

template void faest_pack_public_key(uint8_t*, const public_key<v2::keccak_then_mayo_128_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::keccak_then_mayo_128_f>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::keccak_then_mayo_192_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::keccak_then_mayo_192_f>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::keccak_then_mayo_256_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::keccak_then_mayo_256_f>*);

template void faest_unpack_public_key(public_key<v2::keccak_then_mayo_128_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::keccak_then_mayo_128_f>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::keccak_then_mayo_192_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::keccak_then_mayo_192_f>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::keccak_then_mayo_256_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::keccak_then_mayo_256_f>*, const uint8_t*);

template bool faest_pubkey<v2::keccak_then_mayo_128_s>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v2::keccak_then_mayo_128_f>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v2::keccak_then_mayo_192_s>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v2::keccak_then_mayo_192_f>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v2::keccak_then_mayo_256_s>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v2::keccak_then_mayo_256_f>(uint8_t*, const uint8_t*);
#endif

#if defined WITH_RAINHASH

// ----- v1 -----
template bool faest_unpack_secret_key(secret_key<v1::rainhash_then_mayo_128_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v1::rainhash_then_mayo_128_f>*, const uint8_t*);


template void faest_pack_public_key(uint8_t*, const public_key<v1::rainhash_then_mayo_128_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v1::rainhash_then_mayo_128_f>*);

template void faest_unpack_public_key(public_key<v1::rainhash_then_mayo_128_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v1::rainhash_then_mayo_128_f>*, const uint8_t*);

template bool faest_pubkey<v1::rainhash_then_mayo_128_s>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v1::rainhash_then_mayo_128_f>(uint8_t*, const uint8_t*);

// ----- v2 -----
template bool faest_unpack_secret_key(secret_key<v2::rainhash_then_mayo_128_s>*, const uint8_t*);
template bool faest_unpack_secret_key(secret_key<v2::rainhash_then_mayo_128_f>*, const uint8_t*);


template void faest_pack_public_key(uint8_t*, const public_key<v2::rainhash_then_mayo_128_s>*);
template void faest_pack_public_key(uint8_t*, const public_key<v2::rainhash_then_mayo_128_f>*);

template void faest_unpack_public_key(public_key<v2::rainhash_then_mayo_128_s>*, const uint8_t*);
template void faest_unpack_public_key(public_key<v2::rainhash_then_mayo_128_f>*, const uint8_t*);

template bool faest_pubkey<v2::rainhash_then_mayo_128_s>(uint8_t*, const uint8_t*);
template bool faest_pubkey<v2::rainhash_then_mayo_128_f>(uint8_t*, const uint8_t*);

#endif


// THE VOLE STUFF

#if defined WITH_KECCAK

// keccak_then_mayo functions

// ----- v1 -----
template bool vole_prove
<faest::v1::keccak_then_mayo_128_s>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v1::keccak_then_mayo_128_s>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v1::keccak_then_mayo_128_f>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v1::keccak_then_mayo_128_f>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v1::keccak_then_mayo_192_s>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v1::keccak_then_mayo_192_s>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v1::keccak_then_mayo_192_f>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v1::keccak_then_mayo_192_f>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v1::keccak_then_mayo_256_s>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v1::keccak_then_mayo_256_s>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v1::keccak_then_mayo_256_f>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v1::keccak_then_mayo_256_f>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);

// ----- v2 -----
template bool vole_prove
<faest::v2::keccak_then_mayo_128_s>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v2::keccak_then_mayo_128_s>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v2::keccak_then_mayo_128_f>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v2::keccak_then_mayo_128_f>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v2::keccak_then_mayo_192_s>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v2::keccak_then_mayo_192_s>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v2::keccak_then_mayo_192_f>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v2::keccak_then_mayo_192_f>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v2::keccak_then_mayo_256_s>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v2::keccak_then_mayo_256_s>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);


template bool vole_prove
<faest::v2::keccak_then_mayo_256_f>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v2::keccak_then_mayo_256_f>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional);

#endif

#if defined WITH_RAINHASH
// keccak_then_mayo functions

// ----- v1 -----
template bool vole_prove
<faest::v1::rainhash_then_mayo_128_s>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* m_pub,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, 
                uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v1::rainhash_then_mayo_128_s>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional);


template bool vole_prove
<faest::v1::rainhash_then_mayo_128_f>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* m_pub,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, 
                uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v1::rainhash_then_mayo_128_f>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional);

// ----- v2 -----
template bool vole_prove
<faest::v2::rainhash_then_mayo_128_s>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* m_pub,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, 
                uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v2::rainhash_then_mayo_128_s>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional);

template bool vole_prove
<faest::v2::rainhash_then_mayo_128_f>
(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* m_pub,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, 
                uint8_t* salt, uint8_t* r_additional);
template bool vole_verify
<faest::v2::rainhash_then_mayo_128_f>
(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional);

#endif


template <typename P> 
void serialize_pk(uint8_t* pk, const uint8_t* expanded_pk, const uint8_t* msg_hash);

template <typename P> 
void serialize_sk(uint8_t* sk, const uint8_t* pk, const uint8_t* s, const uint8_t* salt, const uint8_t* witness);

#if defined WITH_KECCAK
// ----- v1 ----- Paramter getter
extern "C" {
    void get_keccak_then_mayo128sv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::keccak_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo128fv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::keccak_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo192sv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::keccak_then_mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo192fv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::keccak_then_mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo256sv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::keccak_then_mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo256fv1_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v1::keccak_then_mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
}

// ----- v2 ----- Paramter getter
extern "C" {
    void get_keccak_then_mayo128sv2_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v2::keccak_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo128fv2_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v2::keccak_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo192sv2_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v2::keccak_then_mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo192fv2_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v2::keccak_then_mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo256sv2_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v2::keccak_then_mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
        void get_keccak_then_mayo256fv2_parameters(size_t *chal1_size,
                                   size_t *r_size,
                                   size_t *u_size,
                                   size_t *v_size,
                                   size_t *forest_size,
                                   size_t *iv_pre_size,
                                   size_t *hashed_leaves_size,
                                   size_t *proof_size,
                                   size_t *proof1_size,
                                   size_t *packed_pk_size,
                                   size_t *packed_sk_size,
                                   size_t *random_seed_size,
                                   size_t *pk_seed_size,
                                   size_t *p1_size,
                                   size_t *p2_size,
                                   size_t *p3_size,
                                   size_t *h_size,
                                   size_t *s_size) {

        using P = faest::v2::keccak_then_mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
}
// ----- V1 -----
// 128s/f
extern "C" {
    bool keccak_then_mayo128sv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo128sv1_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);

        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }


    bool keccak_then_mayo128fv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo128fv1_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);


        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }
}
// 192s/f
extern "C" {
    bool keccak_then_mayo192sv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo192sv1_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);

        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }


    bool keccak_then_mayo192fv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo192fv1_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);


        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }
}
// 256s/f
extern "C" {
    bool keccak_then_mayo256sv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo256sv1_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);

        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }


    bool keccak_then_mayo256fv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
    
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo256fv1_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v1::keccak_then_mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);


        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }
}

// ----- V2 -----
// 128s/f
extern "C" {
    bool keccak_then_mayo128sv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo128sv2_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);

        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }


    bool keccak_then_mayo128fv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo128fv2_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);


        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }
}
// 192s/f
extern "C" {
    bool keccak_then_mayo192sv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo192sv2_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_192_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);

        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }


    bool keccak_then_mayo192fv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo192fv2_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_192_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);


        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }
}
// 256s/f
extern "C" {
    bool keccak_then_mayo256sv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo256sv2_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_256_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);

        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }


    bool keccak_then_mayo256fv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
    
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                s, rand, salt, r_additional);
    }
    bool keccak_then_mayo256fv2_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional) {
        using P = faest::v2::keccak_then_mayo_256_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);


        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, r_additional);
    }
}

#endif


#if defined WITH_RAINHASH

// ----- v1 ----- Paramter getter
extern "C" {
void get_rainhash_then_mayo128sv1_parameters(size_t *chal1_size,
                                size_t *r_size,
                                size_t *u_size,
                                size_t *v_size,
                                size_t *forest_size,
                                size_t *iv_pre_size,
                                size_t *hashed_leaves_size,
                                size_t *proof_size,
                                size_t *proof1_size,
                                size_t *packed_pk_size,
                                size_t *packed_sk_size,
                                size_t *random_seed_size,
                                size_t *pk_seed_size,
                                size_t *p1_size,
                                size_t *p2_size,
                                size_t *p3_size,
                                size_t *h_size,
                                size_t *s_size) {

        using P = faest::v1::rainhash_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
    void get_rainhash_then_mayo128fv1_parameters(size_t *chal1_size,
                                size_t *r_size,
                                size_t *u_size,
                                size_t *v_size,
                                size_t *forest_size,
                                size_t *iv_pre_size,
                                size_t *hashed_leaves_size,
                                size_t *proof_size,
                                size_t *proof1_size,
                                size_t *packed_pk_size,
                                size_t *packed_sk_size,
                                size_t *random_seed_size,
                                size_t *pk_seed_size,
                                size_t *p1_size,
                                size_t *p2_size,
                                size_t *p3_size,
                                size_t *h_size,
                                size_t *s_size) {

        using P = faest::v1::rainhash_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
// ----- v2 ----- Paramter getter
    void get_rainhash_then_mayo128sv2_parameters(size_t *chal1_size,
                                size_t *r_size,
                                size_t *u_size,
                                size_t *v_size,
                                size_t *forest_size,
                                size_t *iv_pre_size,
                                size_t *hashed_leaves_size,
                                size_t *proof_size,
                                size_t *proof1_size,
                                size_t *packed_pk_size,
                                size_t *packed_sk_size,
                                size_t *random_seed_size,
                                size_t *pk_seed_size,
                                size_t *p1_size,
                                size_t *p2_size,
                                size_t *p3_size,
                                size_t *h_size,
                                size_t *s_size) {

        using P = faest::v2::rainhash_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }
    void get_rainhash_then_mayo128fv2_parameters(size_t *chal1_size,
                                size_t *r_size,
                                size_t *u_size,
                                size_t *v_size,
                                size_t *forest_size,
                                size_t *iv_pre_size,
                                size_t *hashed_leaves_size,
                                size_t *proof_size,
                                size_t *proof1_size,
                                size_t *packed_pk_size,
                                size_t *packed_sk_size,
                                size_t *random_seed_size,
                                size_t *pk_seed_size,
                                size_t *p1_size,
                                size_t *p2_size,
                                size_t *p3_size,
                                size_t *h_size,
                                size_t *s_size) {

        using P = faest::v2::rainhash_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;

        *chal1_size        = CP::VOLE_CHECK::CHALLENGE_BYTES;
        
        *u_size            = CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *v_size            = P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block);
        *forest_size       = P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>);
        *iv_pre_size       = sizeof(faest::block128);
        *hashed_leaves_size = P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len;
        *proof_size        = VOLE_PROOF_BYTES<P>;
        *proof1_size        = CP::VOLE_COMMIT_SIZE;
        *packed_pk_size    = faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
        *packed_sk_size = faest::VOLEMAYO_SECRET_SIZE_BYTES<S>;

        *pk_seed_size = VOLEMAYO_PK_SEED_BYTES<S>;
        *p1_size = VOLEMAYO_P1_SIZE_BYTES<S>;
        *p2_size = VOLEMAYO_P2_SIZE_BYTES<S>;
        *p3_size =  VOLEMAYO_P3_SIZE_BYTES<S>;
        
        *s_size =  VOLEMAYO_S_BYTES<S>;
    }

    void rain_hash_512_7_c(uint8_t* output, size_t  outlen, const uint8_t* input, size_t inlen) {
        // set_0xff_params();

        // checking for input length to be 64
        for (size_t i = 0; i < 64; i++) {
            assert(input != NULL);
        }

        uint8_t hash_output[64];
        rain_hash(input, hash_output);

        assert(outlen <= 64);
        assert(outlen >= 32);   // to maintain minimum 128-bit security
        // returning only required outlen from the hash
        for (size_t i = 0; i < outlen; i++) {
            output[i] = hash_output[i];
        }

    }
}
// V1
// 128s/f
extern "C" {
    bool rainhash_then_mayo128sv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc, uint8_t* rain_mat,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, 
                uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v1::rainhash_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                rain_rc, rain_mat,
                s, skr_ptr, open, nonce, salt, r_additional);
    }
    bool rainhash_then_mayo128sv1_verify(const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional) {
        using P = faest::v1::rainhash_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);

        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, rain_rc, rain_mat, r_additional);
    }


    bool rainhash_then_mayo128fv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc, uint8_t* rain_mat,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, 
                uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v1::rainhash_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                rain_rc, rain_mat,
                s, skr_ptr, open, nonce, salt, r_additional);
    }
    bool rainhash_then_mayo128fv1_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional) {
        using P = faest::v1::rainhash_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);


        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, rain_rc, rain_mat, r_additional);
    }
}
// V2
// 128s/f
extern "C" {
    bool rainhash_then_mayo128sv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc, uint8_t* rain_mat,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, 
                uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v2::rainhash_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                rain_rc, rain_mat,
                s, skr_ptr, open, nonce, salt, r_additional);
    }
    bool rainhash_then_mayo128sv2_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional) {
        using P = faest::v2::rainhash_then_mayo_128_s;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);

        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, rain_rc, rain_mat, r_additional);
    }


    bool rainhash_then_mayo128fv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc, uint8_t* rain_mat,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, 
                uint8_t* salt, uint8_t* r_additional) {
        using P = faest::v2::rainhash_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        
        return vole_prove<P>(proof, random_seed, random_seed_len, 
                expanded_pk, msg_hash,
                rain_rc, rain_mat,
                s, skr_ptr, open, nonce, salt, r_additional);
    }
    bool rainhash_then_mayo128fv2_verify( const uint8_t* proof, size_t proof_size,
                            uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional) {
        using P = faest::v2::rainhash_then_mayo_128_f;
        using CP = P::CONSTS;
        constexpr auto S = P::secpar_v;
        assert(proof_size == VOLE_PROOF_BYTES<P>);


        return vole_verify<P>(proof, proof_size, expanded_pk, msg_hash, rain_rc, rain_mat, r_additional);
    }
}
#endif

    // clang-format on

} // namespace faest
