#ifndef FAEST_HPP
#define FAEST_HPP

#include <cstdint>

#include "constants.hpp"
#include "parameters.hpp"
#include "prgs.hpp"
#include "vector_com.hpp"

namespace faest
{

// THE VOLE STUFF

template <typename P>
constexpr std::size_t VOLE_PROOF_BYTES =
    P::CONSTS::VOLE_COMMIT_SIZE 
    + P::CONSTS::VOLE_CHECK::PROOF_BYTES 
    + (P::OWF_CONSTS::WITNESS_BITS + 7) / 8 
    + P::CONSTS::QS::PROOF_BYTES 
    + P::bavc_t::OPEN_SIZE 
    + P::secpar_bytes + 16 
    + P::grinding_counter_size;

/* 
#if defined WITH_KECCAK
template <typename P>
bool vole_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* cpk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt);

template <typename P>
bool vole_verify(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* cpk, uint8_t* msg_hash);
#endif


#if defined WITH_RAINHASH
template <typename P>
bool vole_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* cpk, uint8_t* msg_hash,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* rand, uint8_t* salt);

template <typename P>
bool vole_verify(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* cpk, uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat);
#endif
 */

} // namespace faest

#endif
