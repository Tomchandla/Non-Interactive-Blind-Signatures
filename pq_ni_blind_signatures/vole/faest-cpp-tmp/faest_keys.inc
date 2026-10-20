#ifndef FAEST_KEYS_INC
#define FAEST_KEYS_INC

#include "aes.hpp"
#include "constants.hpp"
#include "faest_keys.hpp"
#include "gfsmall.hpp"
#include "parameters.hpp"

namespace faest
{

template <typename P> bool faest_unpack_secret_key(secret_key<P>* unpacked, const uint8_t* packed)
{
    constexpr auto S = P::secpar_v;
    faest_unpack_public_key(&unpacked->pk, packed);
    packed += FAEST_PUBLIC_KEY_BYTES<P>;
    memset(&unpacked->witness[0], 0, sizeof(unpacked->witness));
    memcpy(&unpacked->witness[0], packed, NIBS_WITNESS_BYTES<P> + VOLEMAYO_S_BYTES<S>);
    return true;
}

template <typename P> void faest_pack_public_key(uint8_t* packed, const public_key<P>* unpacked)
{
    constexpr auto S = P::secpar_v;
    memcpy(packed, (const unsigned char*)unpacked->mayo_expanded_pk,
           VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>);
    packed += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>;
    memcpy(packed, &unpacked->msg[0], HASHED_MSG_SIZE_BYTES<S>);
}

template <typename P> void faest_unpack_public_key(public_key<P>* unpacked, const uint8_t* packed)
{
    constexpr auto S = P::secpar_v;
    memset(&unpacked->msg[0], 0, sizeof(unpacked->msg));
    memcpy((unsigned char*)unpacked->mayo_expanded_pk, packed,
           VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>);
    packed += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S>;
    memcpy(&unpacked->msg[0], packed, HASHED_MSG_SIZE_BYTES<S>);
}

template <typename P>
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed, secret_key<P>* sk)
{
    if (!faest_unpack_secret_key(sk, sk_packed))
        return false;
    faest_pack_public_key(pk_packed, &sk->pk);
    return true;
}

} // namespace faest

#endif
