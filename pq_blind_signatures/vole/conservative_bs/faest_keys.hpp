#ifndef FAEST_KEYS_HPP
#define FAEST_KEYS_HPP

#include "aes.hpp"
#include "block.hpp"
#include "constants.hpp"
#include "parameters.hpp"


namespace faest
{

#if defined WITH_KECCAK
// The size of the FAEST secret key is the size of the secret key and the input to the OWF.
template <typename P>
constexpr std::size_t FAEST_SECRET_KEY_BYTES = VOLEMAYO_SECRET_KEY_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_SECRET_SIZE_BYTES<P::secpar_v>;

// The size of the public key is the size of the input and the output of the OWF.
template <typename P>
constexpr std::size_t FAEST_PUBLIC_KEY_BYTES = VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_PUBLIC_SIZE_BYTES;
#endif

#if defined WITH_RAINHASH
// The size of the FAEST secret key is the size of the secret key and the input to the OWF.
template <typename P>
constexpr std::size_t FAEST_SECRET_KEY_BYTES = VOLEMAYO_SECRET_KEY_SIZE_BYTES<P::secpar_v> + VOLERAINHASH_SECRET_SIZE_BYTES<P::secpar_v>;

// The size of the public key is the size of the input and the output of the OWF.
template <typename P>
constexpr std::size_t FAEST_PUBLIC_KEY_BYTES = VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + VOLERAINHASH_PUBLIC_SIZE_BYTES;
#endif

template <typename P>
struct public_key
{
    #if defined WITH_KECCAK
        // Lets jsut directly get the P's instead of generating from the seed, in the paper the pk size will be just the seed size
        // msg should not be here, change later
        P::OWF_CONSTS::block_t msg[(HASHED_MSG_SIZE_BITS<P::secpar_v> + 127) / 128];
        uint64_t mayo_expanded_pk[VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>];
    #endif

    #if defined WITH_RAINHASH
        // Lets jsut directly get the P's instead of generating from the seed, in the paper the pk size will be just the seed size
        // msg should not be here, change later
        P::OWF_CONSTS::block_t msg[(HASHED_MSG_SIZE_BITS<P::secpar_v> + 127) / 128];
        uint64_t mayo_expanded_pk[VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>];

        // The Round consts and matrices are fixed, let's put them in pk for now
        P::OWF_CONSTS::block_t rain_rc_qs[(VOLERAINHASH_RC_SIZE_BITS + 127) / 128];
        P::OWF_CONSTS::block_t rain_mat_qs[(VOLERAINHASH_MAT_SIZE_BITS + 127) / 128];
        P::OWF_CONSTS::block_t pk_output[(VOLERAINHASH_PK_OUTPUT_BYTES*8 + 127) / 128];          // the output of rainhash
    #endif
};

template <typename P> struct secret_key
{
    public_key<P> pk;

    #if defined WITH_KECCAK
        // NOTE: Contains the s of mayo and input, output and witness of keccak
        // Two times the keccak witness because of 2 keccak calls
        vole_block sk[(VOLEMAYO_S_BITS<P::secpar_v> + VOLEKECCAK_WITNESS_SIZE_BITS<P::secpar_v> + 127) / 128];     
        vole_block witness[(VOLEMAYO_S_BITS<P::secpar_v> + VOLEKECCAK_WITNESS_SIZE_BITS<P::secpar_v> + 127) / 128]; 
    #endif

    #if defined WITH_RAINHASH
        // NOTE: Contains the s of mayo and input, output and witness of keccak
        // Two times the keccak witness because of 2 keccak calls
        vole_block sk[(VOLEMAYO_S_BITS<P::secpar_v> + VOLERAINHASH_WITNESS_SIZE_BITS<P::secpar_v> + 127) / 128];     
        vole_block witness[(VOLEMAYO_S_BITS<P::secpar_v> + VOLERAINHASH_WITNESS_SIZE_BITS<P::secpar_v> + 127) / 128]; 
    #endif  

};

template <typename P> bool faest_unpack_secret_key(secret_key<P>* unpacked, const uint8_t* packed);
template <typename P> void faest_pack_public_key(uint8_t* packed, const public_key<P>* unpacked);
template <typename P> void faest_unpack_public_key(public_key<P>* unpacked, const uint8_t* packed);
template <typename P> bool faest_compute_witness(secret_key<P>* sk);
template <typename P>
bool faest_unpack_sk_and_get_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed,
                                    secret_key<P>* sk);

// Check if a byte string is a valid secret key. sk_packed must be FAEST_SECRET_KEY_BYTES long.
template <typename P> bool faest_seckey(const uint8_t* sk_packed);

// Find the public key corresponding to a given secret key. Returns true if sk_packed is a valid
// secret key, and false otherwise. For key generation, this function is intended to be called
// repeatedly on random values of sk_packed until a valid key is found. pk_packed must be
// FAEST_PUBLIC_KEY_BYTES long, while sk_packed must be FAEST_SECRET_KEY_BYTES long.
template <typename P> bool faest_pubkey(uint8_t* pk_packed, const uint8_t* sk_packed);

} // namespace faest

#endif // FAEST_KEYS_H
