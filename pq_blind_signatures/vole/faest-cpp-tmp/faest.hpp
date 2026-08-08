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

} // namespace faest

#endif
