#ifndef FAEST_KEYS_HPP
#define FAEST_KEYS_HPP

#include "aes.hpp"
#include "block.hpp"
#include "constants.hpp"
#include "parameters.hpp"

#if !defined WITH_RAINHASH
#error "this tree builds the NIBS (RainHash/LowMC/MAYO) circuits only; define WITH_RAINHASH"
#endif

namespace faest
{

// Packed forms used by the prover:
//   public  = MAYO expanded public key || m
//   secret  = public || NIBS witness (nibs_layout) || MAYO preimage s
template <typename P>
constexpr std::size_t NIBS_WITNESS_BYTES = nibs_layout<P::secpar_v, P::owf_v>::WITNESS_BYTES;

template <typename P>
constexpr std::size_t FAEST_PUBLIC_KEY_BYTES = VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;

template <typename P>
constexpr std::size_t FAEST_SECRET_KEY_BYTES =
    FAEST_PUBLIC_KEY_BYTES<P> + NIBS_WITNESS_BYTES<P> + VOLEMAYO_S_BYTES<P::secpar_v>;

template <typename P> struct public_key
{
    // statement x = (vk, m)
    P::OWF_CONSTS::block_t msg[(HASHED_MSG_SIZE_BITS<P::secpar_v> + 127) / 128];
    uint64_t mayo_expanded_pk[VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>];
};

template <typename P> struct secret_key
{
    public_key<P> pk;
    vole_block witness[(8 * NIBS_WITNESS_BYTES<P> + VOLEMAYO_S_BITS<P::secpar_v> + 127) / 128];
};

template <typename P> bool faest_unpack_secret_key(secret_key<P>* unpacked, const uint8_t* packed);
template <typename P> void faest_pack_public_key(uint8_t* packed, const public_key<P>* unpacked);
template <typename P> void faest_unpack_public_key(public_key<P>* unpacked, const uint8_t* packed);
template <typename P>
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed,
                                    secret_key<P>* sk);

} // namespace faest

#endif // FAEST_KEYS_HPP
