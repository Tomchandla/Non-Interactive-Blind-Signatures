#ifndef OWF_PROOF_H
#define OWF_PROOF_H

#include "parameters.hpp"

namespace faest
{

template <secpar S, bool verifier, std::size_t max_deg>
    requires(max_deg >= 1)
struct quicksilver_state;

template <typename P> struct public_key;

template <typename P>
constexpr std::size_t FAEST_PROOF_BYTES =
    P::CONSTS::VOLE_COMMIT_SIZE + P::CONSTS::VOLE_CHECK::PROOF_BYTES +
    P::OWF_CONSTS::WITNESS_BITS / 8 + P::CONSTS::QS::PROOF_BYTES + P::bavc_t::OPEN_SIZE +
    P::secpar_bytes + 16 + P::grinding_counter_size;

template <typename P, bool verifier>
void owf_constraints(quicksilver_state<P::secpar_v, verifier, P::OWF_CONSTS::QS_DEGREE>* state,
                     const public_key<P>* pk, unsigned char* chal2);

} // namespace faest

#endif
