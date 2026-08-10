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
    #if defined WITH_KECCAK
        size_t sk_offset_bytes = 0;
        memcpy((unsigned char *) unpacked->pk.mayo_expanded_pk, packed, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
        sk_offset_bytes += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

        memcpy(&unpacked->pk.msg[0], packed + sk_offset_bytes, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
        sk_offset_bytes += HASHED_MSG_SIZE_BYTES<P::secpar_v>;

        // getting the secret part
        memcpy(&unpacked->sk[0], packed + sk_offset_bytes, VOLEMAYO_WITNESS_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_WITNESS_SIZE_BYTES<P::secpar_v>);       // contains the s and r
        memcpy(&unpacked->witness[0], packed + sk_offset_bytes, VOLEMAYO_WITNESS_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_WITNESS_SIZE_BYTES<P::secpar_v>);    // basically copying the same thing here as sk
    #endif

    #if defined WITH_RAINHASH
        // the mayo part
        size_t sk_offset_bytes = 0;
        memcpy((unsigned char *) unpacked->pk.mayo_expanded_pk, packed, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
        sk_offset_bytes += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;
        
        memcpy(&unpacked->pk.msg[0], packed + sk_offset_bytes, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
        sk_offset_bytes += HASHED_MSG_SIZE_BYTES<P::secpar_v>;

        // the rainhash part
        memcpy(&unpacked->pk.rain_rc_qs[0], packed + sk_offset_bytes, VOLERAINHASH_RC_SIZE_BYTES);
        sk_offset_bytes += VOLERAINHASH_RC_SIZE_BYTES;
        memcpy(&unpacked->pk.rain_mat_qs[0], packed + sk_offset_bytes, VOLERAINHASH_MAT_SIZE_BYTES);
        sk_offset_bytes += VOLERAINHASH_MAT_SIZE_BYTES;
        memcpy(&unpacked->pk.pk_output[0], packed + sk_offset_bytes, VOLERAINHASH_PK_OUTPUT_BYTES);
        sk_offset_bytes += VOLERAINHASH_PK_OUTPUT_BYTES;

        // getting the secret part
        memcpy(&unpacked->sk[0], packed + sk_offset_bytes, VOLEMAYO_WITNESS_SIZE_BYTES<P::secpar_v> + VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>);       // contains the s and r
        memcpy(&unpacked->witness[0], packed + sk_offset_bytes, VOLEMAYO_WITNESS_SIZE_BYTES<P::secpar_v> + VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>);    // basically copying the same thing here as sk
    #endif

    return true;
}

template <typename P> void faest_pack_public_key(uint8_t* packed, const public_key<P>* unpacked)
{
    #if defined WITH_KECCAK
        memcpy(packed, (unsigned char *) unpacked->mayo_expanded_pk, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
        packed += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

        memcpy(packed, &unpacked->msg, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
    #endif

    #if defined WITH_RAINHASH
        // the mayo part
        memcpy(packed, (unsigned char *) unpacked->mayo_expanded_pk, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
        packed += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;
        memcpy(packed, &unpacked->msg, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
        packed += HASHED_MSG_SIZE_BYTES<P::secpar_v>;

        // The rain pk
        // NOTE: Stored coloumn major!!
        memcpy(packed, &unpacked->rain_rc_qs, VOLERAINHASH_RC_SIZE_BYTES);
        packed += VOLERAINHASH_RC_SIZE_BYTES; 
        memcpy(packed, &unpacked->rain_mat_qs, VOLERAINHASH_MAT_SIZE_BYTES);
        packed += VOLERAINHASH_MAT_SIZE_BYTES; 
        memcpy(packed, &unpacked->pk_output, VOLERAINHASH_PK_OUTPUT_BYTES);    // NOTE: This is size 0 here, don't care
    #endif

}

template <typename P> void faest_unpack_public_key(public_key<P>* unpacked, const uint8_t* packed)
{
    #if defined WITH_KECCAK
        memcpy((unsigned char *) unpacked->mayo_expanded_pk, packed, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
        packed += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

        memcpy(&unpacked->msg[0], packed, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
        packed += HASHED_MSG_SIZE_BYTES<P::secpar_v>;
    #endif

    #if defined WITH_RAINHASH
        // mayo pk
        memcpy((unsigned char *) unpacked->mayo_expanded_pk, packed, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
        packed += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

        memcpy(&unpacked->msg[0], packed, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
        packed += HASHED_MSG_SIZE_BYTES<P::secpar_v>;

        // rainhash pk
        memcpy(&unpacked->rain_rc_qs[0], packed, VOLERAINHASH_RC_SIZE_BYTES);
        packed += VOLERAINHASH_RC_SIZE_BYTES;

        memcpy(&unpacked->rain_mat_qs[0], packed, VOLERAINHASH_MAT_SIZE_BYTES);
        packed += VOLERAINHASH_MAT_SIZE_BYTES;

        memcpy(&unpacked->pk_output[0], packed, VOLERAINHASH_PK_OUTPUT_BYTES);
        packed += VOLERAINHASH_PK_OUTPUT_BYTES;
    #endif
    
}

template <typename P> bool faest_compute_witness(secret_key<P>* sk)
{
    return true;
}

template <typename P>
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed, secret_key<P>* sk)
{
    if (!faest_unpack_secret_key(sk, sk_packed))
        return false;

    faest_pack_public_key(pk_packed, &sk->pk);
    return true;
}


template <typename P> bool faest_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed)
{
    faest::secret_key<P> sk;
    return faest_unpack_sk_and_get_pubkey(pk_packed, sk_packed, &sk);
}


} // namespace faest

#endif
