#ifndef OWF_PROOF_INC
#define OWF_PROOF_INC

#include "aes.hpp"
#include "hash.hpp"
#include "constants.hpp"
#include "faest_keys.hpp"
#include "owf_proof.hpp"
#include "owf_proof_tools.hpp"
#include "parameters.hpp"
#include "quicksilver.hpp"

#include "rainhash_plain/rain_hash.h"
#include "lowmc_plain/lowmc.hpp"
#include <array>
#include <vector>

#include <iostream>
#include <vector>

namespace faest
{

template <secpar S> constexpr static std::size_t N_WD = secpar_to_bits(S) / 32;

template <secpar S, owf O> constexpr static std::size_t S_ENC = OWF_CONSTANTS<S, O>::OWF_ENC_SBOXES;

template <secpar S, owf O> using owf_block = OWF_CONSTANTS<S, O>::block_t;

template <typename QS, typename OC>
using owf_round_key_bits =
    std::array<quicksilver_gf2<QS>, 8 * OC::OWF_BLOCK_SIZE*(OC::OWF_ROUNDS + 1)>;

template <typename QS, typename OC>
using owf_round_key_bytes =
    std::array<quicksilver_gfsecpar<QS>, OC::OWF_BLOCK_SIZE*(OC::OWF_ROUNDS + 1)>;


// load 128 consecutive bits from s into QS GF(2) values, then combine them into a GF(2^secpar)
// value in the GF(2^128) subfield
template <typename QS>
static inline quicksilver_gfsecpar<QS, 0> load_const_128_bits_and_combine(const QS* state,
                                                                        const void* s)
{
    auto input_bits = state->template const_gf2_array<128, 0>();
    for (size_t bit_j = 0; bit_j < 128; ++bit_j)
        input_bits[bit_j] = quicksilver_gf2<QS, 0>(poly1::load(((uint8_t*)s)[bit_j/8], bit_j%8), state);
    return quicksilver_gfsecpar<QS, 0>::combine_128_bits(input_bits.data());
}


template <typename QS, size_t n>
static void lift_bits_8b(const std::array<quicksilver_gf2<QS>, 8 * n>& bits,
                      std::array<quicksilver_gfsecpar<QS>, n>& bytes)
{
    for (size_t byte_i = 0; byte_i < n; ++byte_i)
        bytes[byte_i] = quicksilver_gfsecpar<QS>::combine_8_bits(&bits[8 * byte_i]);
}
// The 4 bits part
template <typename QS, size_t n>
static void lift_bits_4b(const std::array<quicksilver_gf2<QS>, 4 * n>& bits,
                      std::array<quicksilver_gfsecpar<QS>, n>& bytes)
{
    for (size_t byte_i = 0; byte_i < n; ++byte_i)
        bytes[byte_i] = quicksilver_gfsecpar<QS>::combine_4_bits(&bits[4 * byte_i]);
}
// The 1 bit part
template <typename QS, size_t n>
static void lift_bit_1b(const std::array<quicksilver_gf2<QS>, n>& bits,
                      std::array<quicksilver_gfsecpar<QS>, n>& bytes)
{
    for (size_t byte_i = 0; byte_i < n; ++byte_i)
        bytes[byte_i] = quicksilver_gfsecpar<QS>::combine_1_bit(&bits[byte_i]);
}

// load 8 consecutive bits from s into QS GF(2) values, then combine them into a GF(2^secpar)
// value in the GF(2^8) subfield
template <typename QS>
static inline quicksilver_gfsecpar<QS, 0> load_const_8_bits_and_combine(const QS* state,
                                                                        const void* s)
{
    auto input_bits = state->template const_gf2_array<8, 0>();
    for (size_t bit_j = 0; bit_j < 8; ++bit_j)
        input_bits[bit_j] = quicksilver_gf2<QS, 0>(poly1::load(*(uint8_t*)s, bit_j), state);
    return quicksilver_gfsecpar<QS, 0>::combine_8_bits(input_bits.data());
}
template <typename QS>
static inline quicksilver_gfsecpar<QS, 0> load_const_4_bits_and_combine(const QS* state,
                                                                        const void* s, bool msb_4_bits)
{
    auto input_bits = state->template const_gf2_array<4, 0>();
    size_t bit_offset = 0;
    if (msb_4_bits) {
        bit_offset = 4;
    }
    for (size_t bit_j = 0; bit_j < 4; ++bit_j)
        input_bits[bit_j] = quicksilver_gf2<QS, 0>(poly1::load(*(uint8_t*)s, bit_j + bit_offset), state);
    return quicksilver_gfsecpar<QS, 0>::combine_4_bits(input_bits.data());
}
template <typename QS>
static inline quicksilver_gfsecpar<QS, 0> load_const_1_bit_and_combine(const QS* state,
                                                                        const void* s, uint8_t idx)
{
    auto input_bit = state->template const_gf2_array<1, 0>();
    input_bit[0] = quicksilver_gf2<QS, 0>(poly1::load(*(uint8_t*)s, idx), state);
    return quicksilver_gfsecpar<QS, 0>::combine_1_bit(input_bit.data());
}

static inline uint8_t mod_reduce_gf16(size_t a) {

    size_t c = a;
    for(size_t i = 7; i > 3; i--) {
        if ((c >> i) & 1) {
            c ^= VOLEMAYO_MOD << (i - 4);
        }
    }
    return (uint8_t)c;
}
// carry less mult
static inline uint8_t mul_mod_gf16(uint8_t a, uint8_t b) {

    size_t c = 0;
    while (b) {
        if (b & 1) {
            c ^= a;
        }
        a <<= 1;
        b >>= 1;
    }

    return mod_reduce_gf16(c);

}



// ----------------------------------------------------------------------------
// Lane-parameterized input loader.
//
// The existing enc_constraints_fwd_first_round special-cases offset==0
// (lane0 = public pk->msg, lane1 = witness, lanes 2-3 = 0xff). Generalize:
// each of the 4 lanes is either a 128-bit public constant or a witness load
// at an explicit bit offset. lane_const[i] != nullptr => constant, else load
// witness at lane_off[i]. Use this in BOTH places the input is reconstructed
// (enc_constraints_fwd_first_round AND the feed-forward re-load inside
// enc_constraints_fwd_last_round_and_check) -- same lane spec both times.
// ----------------------------------------------------------------------------

template <typename QS, typename P, owf O, size_t deg>
requires(is_owf_with_rainhash_then_mayo(O))
static void load_rain_input_lanes(QS* qs_state,
    quicksilver_gfsecpar<QS, deg>* state,
    const uint8_t* const lane_const[4], const size_t lane_off[4]) {

    for (size_t i = 0; i < 4; i++) {
        if (lane_const[i] != nullptr)
            state[i] = load_const_128_bits_and_combine(qs_state, lane_const[i]);
        else
            state[i] = qs_state->load_witness_128_bits_and_combine(lane_off[i]);
    }
}


// THE RAINHASH STUFF
template <typename QS, typename P, owf O, size_t deg>
requires(is_owf_with_rainhash_then_mayo(O))
static void 
enc_constraints_fwd_first_round(QS* qs_state,
    quicksilver_gfsecpar<QS, deg>* in_sbox, const public_key<P>* pk,
    size_t which_rainhash_witness_offset,
    const uint8_t* const lane_const[4], const size_t lane_off[4]) {

    using OC = P::OWF_CONSTS;

    size_t witness_offset_bit_curr_state = which_rainhash_witness_offset;

    quicksilver_gfsecpar<QS, deg> state[4];
    load_rain_input_lanes<QS, P, O, deg>(qs_state, state, lane_const, lane_off);

    // if constexpr (!QS::is_verifier) {
    //     for (size_t i = 0; i < 4; i++) {
    //         size_t tmp_1 = 0;
    //         quicksilver_gfsecpar<QS, 1> a = state[i];
    //         memcpy(&tmp_1, &a.value().data, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         memcpy(&tmp_1, (uint8_t*)&a.value().data + 8, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         std::cout << "\n";
    //     }   
    // }

    size_t witness_offset_byte_curr_state = 0;
    quicksilver_gfsecpar<QS, deg> rc[4];
    for (size_t i = 0; i < 4; i++) {
        rc[i] = load_const_128_bits_and_combine(qs_state, (uint8_t*)&rain_roundconst + witness_offset_byte_curr_state);
        witness_offset_byte_curr_state += 16;
    }

    // if constexpr (!QS::is_verifier) {
    //     for (size_t i = 0; i < 4; i++) {
    //         size_t tmp_1 = 0;
    //         quicksilver_gfsecpar<QS, 1> a = rc[i];
    //         memcpy(&tmp_1, &a.value().data, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         memcpy(&tmp_1, (uint8_t*)&a.value().data + 8, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         std::cout << "\n";
    //     }   
    // }

    // adding the round const gf128 * 4 wise
    for (size_t i = 0; i < 4; i++) {
        in_sbox[i] = state[i] + rc[i];
        // in_sbox[i] = state[i];
    }   
}

template <typename QS, typename P, owf O, size_t deg>
requires(is_owf_with_rainhash_then_mayo(O))
static void 
enc_constraints_fwd_nth_round(QS* qs_state, size_t round_idx,
    quicksilver_gfsecpar<QS, deg>* out_sbox,
    quicksilver_gfsecpar<QS, deg>* in_sbox, const public_key<P>* pk, size_t which_rainhash_witness_offset) {

    using OC = P::OWF_CONSTS;

    // full gadgets [in | 7 states | out]: round r's sbox output at IN_OFF + B*r
    size_t witness_offset_bit_curr_state =
        which_rainhash_witness_offset + VOLERAINHASH_B*(round_idx);

    // quicksilver_gfsecpar<QS, deg> state_secpar[VOLERAINHASH_B];
    quicksilver_gf2<QS, deg> state_bits[VOLERAINHASH_B];
    for (size_t state_bit_idx = 0; state_bit_idx < VOLERAINHASH_B; state_bit_idx++) {
        const auto state_bit = qs_state->load_witness_1_bit(witness_offset_bit_curr_state + state_bit_idx);
        state_bits[state_bit_idx] = state_bit[0];
        // state_secpar[state_bit_idx] = quicksilver_gfsecpar<QS>::combine_1_bit(state_bit.data());
    }    

    witness_offset_bit_curr_state = 0;
    for (size_t state_idx = 0; state_idx < 4; state_idx++) {
        out_sbox[state_idx] = quicksilver_gfsecpar<QS>::combine_128_bits(state_bits + witness_offset_bit_curr_state);
        witness_offset_bit_curr_state += 128;
    }


    // if constexpr (!QS::is_verifier) {
    //     for (size_t i = 0; i < 4; i++) {
    //         size_t tmp_1 = 0;
    //         quicksilver_gfsecpar<QS, 1> a = out_sbox[i];
    //         memcpy(&tmp_1, &a.value().data, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         memcpy(&tmp_1, (uint8_t*)&a.value().data + 8, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         std::cout << "\n";
    //     }   
    // }


    // THE MAT MUL
    // quicksilver_gfsecpar<QS> matmulres[VOLERAINHASH_B];
    quicksilver_gf2<QS, deg> matmulres[VOLERAINHASH_B];
    for (size_t matcol = 0; matcol < VOLERAINHASH_B; matcol++) {
        uint8_t zero = 0;
        quicksilver_gf2<QS, deg> qs_zero = quicksilver_gf2<QS, 0>(poly1::load(zero, 0), qs_state);
        matmulres[matcol] = qs_zero;
        for (size_t matrow = 0; matrow < VOLERAINHASH_B; matrow++) {
            // NOTE: This matrix mult is from the n - 1 th round!!!
            uint8_t* bit = (uint8_t*)&rain_matrix + (round_idx-1)*VOLERAINHASH_B*(VOLERAINHASH_B/8) + matcol*(VOLERAINHASH_B/8) 
                            + matrow/8;

            matmulres[matcol] += AND_GF2_CONST<QS>(state_bits[matrow], (*bit >> matrow%8) & 1);
        }
    }

    size_t matmulres_offset_bit = 0;
    quicksilver_gfsecpar<QS, deg> state[4];
    for (size_t state_idx = 0; state_idx < 4; state_idx++) {
        state[state_idx] = quicksilver_gfsecpar<QS>::combine_128_bits(matmulres + matmulres_offset_bit);
        matmulres_offset_bit += 128;
    }

    if (round_idx != 7) {
        size_t witness_offset_byte_curr_state = 0;
        quicksilver_gfsecpar<QS, deg> rc[4];
        for (size_t i = 0; i < 4; i++) {
            rc[i] = load_const_128_bits_and_combine(qs_state, (uint8_t*)&rain_roundconst + round_idx*VOLERAINHASH_ONE_ROUND_RC_SIZE_BYTES + witness_offset_byte_curr_state);
            witness_offset_byte_curr_state += 16;
        }

        // adding the round const gf128 * 4 wise
        for (size_t state_idx = 0; state_idx < 4; state_idx++) {
            in_sbox[state_idx] = state[state_idx] + rc[state_idx];       
        }
    }
    else {
        for (size_t state_idx = 0; state_idx < 4; state_idx++) {
            in_sbox[state_idx] = state[state_idx];       
        }
    }
    
}

template <typename QS, typename P, owf O, size_t deg>
requires(is_owf_with_rainhash_then_mayo(O))
static void 
enc_constraints_fwd_last_round_and_check(QS* qs_state,
    // quicksilver_gfsecpar<QS, deg>* before_input_xor, quicksilver_gfsecpar<QS, deg>* hash_out, const public_key<P>* pk, size_t which_rainhash_witness_offset) {
    quicksilver_gfsecpar<QS, deg>* before_input_xor, const public_key<P>* pk, size_t which_rainhash_witness_offset, const uint8_t* const lane_const[4], const size_t lane_off[4]) {

    using OC = P::OWF_CONSTS;

    size_t witness_offset_bit_curr_state = 0;

    // if (which_rainhash_witness_offset == 0) {
    //     witness_offset_bit_curr_state = RAND_SIZE_BITS<P::secpar_v> + VOLERAINHASH_B*(7-1); 
    // } else {
    //     witness_offset_bit_curr_state = which_rainhash_witness_offset + VOLERAINHASH_B*(7); 
    // }

    // quicksilver_gf2<QS, deg> state_bits[VOLERAINHASH_B];
    // for (size_t state_bit_idx = 0; state_bit_idx < VOLERAINHASH_B; state_bit_idx++) {
    //     const auto state_bit = qs_state->load_witness_1_bit(witness_offset_bit_curr_state + state_bit_idx);
    //     state_bits[state_bit_idx] = state_bit[0];
    //     // state_secpar[state_bit_idx] = quicksilver_gfsecpar<QS>::combine_1_bit(state_bit.data());
    // }  

    // // quicksilver_gfsecpar<QS, deg> out_sbox[4];
    // // witness_offset_bit_curr_state = 0;
    // // for (size_t state_idx = 0; state_idx < 4; state_idx++) {
    // //     out_sbox[state_idx] = quicksilver_gfsecpar<QS>::combine_128_bits(state_bits + witness_offset_bit_curr_state);
    // //     witness_offset_bit_curr_state += 128;
    // // }

    // // THE MAT MUL
    // // quicksilver_gfsecpar<QS> matmulres[VOLERAINHASH_B];
    // quicksilver_gf2<QS, deg> matmulres[VOLERAINHASH_B];
    // size_t round_idx = 7;
    // for (size_t matcol = 0; matcol < VOLERAINHASH_B; matcol++) {
    //     uint8_t zero = 0;
    //     quicksilver_gf2<QS, deg> qs_zero = quicksilver_gf2<QS, 0>(poly1::load(zero, 0), qs_state);
    //     matmulres[matcol] = qs_zero;
    //     for (size_t matrow = 0; matrow < VOLERAINHASH_B; matrow++) {
    //         // NOTE: This matrix mult is from the n - 1 th round!!!
    //         uint8_t* bit = (uint8_t*)&rain_matrix + (round_idx-1)*VOLERAINHASH_B*(VOLERAINHASH_B/8) + matcol*(VOLERAINHASH_B/8) 
    //                         + matrow/8;

    //         matmulres[matcol] += AND_GF2_CONST<QS>(state_bits[matrow], (*bit >> matrow%8) & 1);
    //     }
    // }

    // quicksilver_gfsecpar<QS, deg> after_mat_mul[4];
    // size_t matmulres_offset_bit = 0;
    // quicksilver_gfsecpar<QS, deg> state[4];
    // for (size_t state_idx = 0; state_idx < 4; state_idx++) {
    //     after_mat_mul[state_idx] = quicksilver_gfsecpar<QS>::combine_128_bits(matmulres + matmulres_offset_bit);
    //     matmulres_offset_bit += 128;
    // }


    // Getting the first round input part
    witness_offset_bit_curr_state = which_rainhash_witness_offset;
    quicksilver_gfsecpar<QS, deg> in_state[4];
    load_rain_input_lanes<QS, P, O, deg>(qs_state, in_state, lane_const, lane_off);

    quicksilver_gfsecpar<QS, deg> hash_out[4];
    for (size_t state_idx = 0; state_idx < 4; state_idx++) {
        hash_out[state_idx] = before_input_xor[state_idx] + in_state[state_idx];       // h = H(m) + m
    }

    // Getting the hash output from witness and checking it with the above computed.
    // Every Rain gadget is [in | 7 states | out]: the output block sits at
    // IN_OFF + B*(NUM_ROUNDS+1).
    witness_offset_bit_curr_state = which_rainhash_witness_offset
                                  + VOLERAINHASH_B * (VOLERAINHASH_NUM_ROUNDS + 1);
    quicksilver_gf2<QS, deg> hash_out_state_bits[VOLERAINHASH_B];
    for (size_t state_bit_idx = 0; state_bit_idx < VOLERAINHASH_B; state_bit_idx++) {
        const auto state_bit = qs_state->load_witness_1_bit(witness_offset_bit_curr_state + state_bit_idx);
        hash_out_state_bits[state_bit_idx] = state_bit[0];
        // state_secpar[state_bit_idx] = quicksilver_gfsecpar<QS>::combine_1_bit(state_bit.data());
    }  

    quicksilver_gfsecpar<QS, deg> hash_output_from_witness[4];
    witness_offset_bit_curr_state = 0;
    for (size_t state_idx = 0; state_idx < 4; state_idx++) {
        hash_output_from_witness[state_idx] = quicksilver_gfsecpar<QS>::combine_128_bits(hash_out_state_bits + witness_offset_bit_curr_state);
        witness_offset_bit_curr_state += 128;
    }

    // std::cout << "witness output :: " << std::endl;
    // if constexpr (!QS::is_verifier) {
    //     for (size_t i = 0; i < 4; i++) {
    //         size_t tmp_1 = 0;
    //         quicksilver_gfsecpar<QS, 1> a = hash_output_from_witness[i];
    //         memcpy(&tmp_1, &a.value().data, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         memcpy(&tmp_1, (uint8_t*)&a.value().data + 8, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         std::cout << "\n";
    //     }   
    // }

    // std::cout << "output :: " << std::endl;
    // if constexpr (!QS::is_verifier) {
    //     for (size_t i = 0; i < 4; i++) {
    //         size_t tmp_1 = 0;
    //         quicksilver_gfsecpar<QS, 1> a = hash_out[i];
    //         memcpy(&tmp_1, &a.value().data, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         memcpy(&tmp_1, (uint8_t*)&a.value().data + 8, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         std::cout << "\n";
    //     }   
    // }


    // std::cout << "cntrst :: " << std::endl;
    // if constexpr (!QS::is_verifier) {
    //     for (size_t i = 0; i < 4; i++) {
    //         size_t tmp_1 = 0;
    //         quicksilver_gfsecpar<QS, 1> a = hash_output_from_witness[i] + hash_out[i];
    //         memcpy(&tmp_1, &a.value().data, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         memcpy(&tmp_1, (uint8_t*)&a.value().data + 8, sizeof(tmp_1));
    //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //         std::cout << "\n";
    //     }   
    // }

    qs_state->add_constraint(hash_output_from_witness[0] + hash_out[0]);
    qs_state->add_constraint(hash_output_from_witness[1] + hash_out[1]);
    qs_state->add_constraint(hash_output_from_witness[2] + hash_out[2]);
    qs_state->add_constraint(hash_output_from_witness[3] + hash_out[3]);

}

template <typename QS, typename P, owf O, size_t deg>
requires(is_owf_with_rainhash_then_mayo(O))
static void 
check_rain_hash_constraints(QS* qs_state,
    quicksilver_gfsecpar<QS, deg>* in_sbox,
    quicksilver_gfsecpar<QS, deg>* out_sbox) {

    constexpr secpar S = QS::secpar_v;
    using OC = P::OWF_CONSTS;

    const size_t poly_deg_plus_one = 6 + 1;  
    quicksilver_gfsecpar<QS, deg + 1> prod[4];

    // The poly mult
    for (size_t sbox_i = 0; sbox_i < VOLERAINHASH_NUM_ROUNDS; sbox_i++) {

        // std::cout << "SBSBSBBSBSBSB " << sbox_i << "\n";

        size_t round_sbox_idx = sbox_i*4;

        // The reduced poly multiplication
        uint8_t deg_2_bits[16];
        memset(deg_2_bits, 0, 16);
        deg_2_bits[15] = deg_2_bits[15] | (0x01 << 3);
        quicksilver_gfsecpar<QS, 0> poly_deg2 = load_const_128_bits_and_combine(qs_state, deg_2_bits);

        /*
            c0 = a0*b0
            c1 = a0*b1 + a1*b0
            c2 = a0*b2 + a1*b1 + a2*b0
            c3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
            c4 = a1*b3 + a2*b2 + a3*b1
            c5 = a2*b3 + a3*b2
            c6 = a3*b3

            d0 = c0 + c4 + a^123 * c6
            d1 = c1 + c4 + c5 + a^123 * c6
            d2 = c2 + a^123 * c4 + c5 + ( 1 + a^246 ) * c6
            d3 = c3 + a^123 * c5 + c6
        */

        //                                  a0*b0
        prod[0] = in_sbox[round_sbox_idx+0]*out_sbox[round_sbox_idx+0]
        //                                  a_3b_1+a_1b_3+a_2b_2
                                        + in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+1] + in_sbox[round_sbox_idx+1]*out_sbox[round_sbox_idx+3] + in_sbox[round_sbox_idx+2]*out_sbox[round_sbox_idx+2]
        //                                  a_3b_3 * a123
                                        + (in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+3])*poly_deg2;

        //                                  a_1b_0+a_0b_1
        prod[1] = in_sbox[round_sbox_idx+1]*out_sbox[round_sbox_idx+0] + in_sbox[round_sbox_idx+0]*out_sbox[round_sbox_idx+1]
        //                                  a_3b_1+a_1b_3+a_2b_2
                                        + in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+1] + in_sbox[round_sbox_idx+1]*out_sbox[round_sbox_idx+3] + in_sbox[round_sbox_idx+2]*out_sbox[round_sbox_idx+2]
        //                                  a_3b_2+a_2b_3
                                        + in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+2] + in_sbox[round_sbox_idx+2]*out_sbox[round_sbox_idx+3]
        //                                  a_3b_3 * a123
                                        + (in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+3])*poly_deg2;

        //                                  a_2b_0+a_0b_2+a_1b_1
        prod[2] = in_sbox[round_sbox_idx+2]*out_sbox[round_sbox_idx+0] + in_sbox[round_sbox_idx+0]*out_sbox[round_sbox_idx+2] + in_sbox[round_sbox_idx+1]*out_sbox[round_sbox_idx+1]
        //                                  (a_3b_1+a_1b_3+a_2b_2
                                        + (in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+1] + in_sbox[round_sbox_idx+1]*out_sbox[round_sbox_idx+3] + in_sbox[round_sbox_idx+2]*out_sbox[round_sbox_idx+2])*poly_deg2
        //                                  a_3b_2+a_2b_3
                                        + in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+2] + in_sbox[round_sbox_idx+2]*out_sbox[round_sbox_idx+3]
        //                                  a_3b_3
                                        + in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+3]
        //                                  a_3b_3 * a123)*a123
                                        + ((in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+3])*poly_deg2)*poly_deg2;

        //                                  a_3b_0+a_0b_3+a_2b_1+a_1b_2
        prod[3] = in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+0] + in_sbox[round_sbox_idx+0]*out_sbox[round_sbox_idx+3] + in_sbox[round_sbox_idx+2]*out_sbox[round_sbox_idx+1] + in_sbox[round_sbox_idx+1]*out_sbox[round_sbox_idx+2]
        //                                  (a_3b_2+a_2b_3)*a123
                                        + (in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+2] + in_sbox[round_sbox_idx+2]*out_sbox[round_sbox_idx+3])*poly_deg2    
        //                                  a_3b_3
                                        + in_sbox[round_sbox_idx+3]*out_sbox[round_sbox_idx+3];
        

        // if constexpr (!QS::is_verifier) {
        //     for (size_t i = 0; i < 4; i++) {
        //         size_t tmp_1 = 0;
        //         quicksilver_gfsecpar<QS, 2> a = prod[i];
        //         memcpy(&tmp_1, &a.value().data, sizeof(tmp_1));
        //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
        //         memcpy(&tmp_1, (uint8_t*)&a.value().data + 8, sizeof(tmp_1));
        //         std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
        //         std::cout << "\n";
        //     }  
        // }

        qs_state->add_constraint(prod[3]);      // deg-3 = 0
        qs_state->add_constraint(prod[2]);      // deg-2 = 0
        qs_state->add_constraint(prod[1]);      // deg-1 = 0
        qs_state->add_constraint(prod[0] + 1);  // deg-0 = 1

    }
    
}

template <typename QS, typename P, owf O>
requires(is_owf_with_rainhash_then_mayo(O))
static void
enc_constraints_rainhash(QS* qs_state, const public_key<P>* pk, size_t which_rainhash_witness_offset,
                         const uint8_t* const lane_const[4], const size_t lane_off[4])
{
    constexpr secpar S = QS::secpar_v;
    using OC = P::OWF_CONSTS;

    quicksilver_gfsecpar<QS, P::OWF_CONSTS::DEG1> in_sbox[(VOLERAINHASH_NUM_ROUNDS + 1) * 4];
    quicksilver_gfsecpar<QS, P::OWF_CONSTS::DEG1> out_sbox[VOLERAINHASH_NUM_ROUNDS * 4];
    // quicksilver_gfsecpar<QS, P::OWF_CONSTS::DEG1> hash_out[4];

    // round 1 partial
    enc_constraints_fwd_first_round<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, &in_sbox[0*4], pk, which_rainhash_witness_offset, lane_const, lane_off);
    // round 1-2
    enc_constraints_fwd_nth_round<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, 1, &out_sbox[0*4], &in_sbox[1*4], pk, which_rainhash_witness_offset);
    // round 2-3
    enc_constraints_fwd_nth_round<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, 2, &out_sbox[1*4], &in_sbox[2*4], pk, which_rainhash_witness_offset);
    // // round 3-4
    enc_constraints_fwd_nth_round<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, 3, &out_sbox[2*4], &in_sbox[3*4], pk, which_rainhash_witness_offset);
    // round 4-5
    enc_constraints_fwd_nth_round<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, 4, &out_sbox[3*4], &in_sbox[4*4], pk, which_rainhash_witness_offset);
    // round 5-6
    enc_constraints_fwd_nth_round<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, 5, &out_sbox[4*4], &in_sbox[5*4], pk, which_rainhash_witness_offset);
    // round 6-7
    enc_constraints_fwd_nth_round<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, 6, &out_sbox[5*4], &in_sbox[6*4], pk, which_rainhash_witness_offset);
    // round 7-the end
    enc_constraints_fwd_nth_round<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, 7, &out_sbox[6*4], &in_sbox[7*4], pk, which_rainhash_witness_offset);
    // just the input sum part 
    enc_constraints_fwd_last_round_and_check<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, &in_sbox[7*4], pk, which_rainhash_witness_offset, lane_const, lane_off);


    check_rain_hash_constraints<QS, P, O, P::OWF_CONSTS::DEG1>(qs_state, in_sbox, out_sbox);

    // size_t witness_offset_bit_curr_state = 0;
    // quicksilver_gfsecpar<QS, P::OWF_CONSTS::DEG1> last_round_sbox_output[4];
    // if (which_rainhash_witness_offset == 0) {
    //     witness_offset_bit_curr_state = RAND_SIZE_BITS<P::secpar_v> + VOLERAINHASH_B*(7-1); 
    // } else {
    //     witness_offset_bit_curr_state = which_rainhash_witness_offset + VOLERAINHASH_B*(7); 
    // }
    // quicksilver_gf2<QS, P::OWF_CONSTS::DEG1> last_round_sbox_output_bits[VOLERAINHASH_B];
    // for (size_t state_bit_idx = 0; state_bit_idx < VOLERAINHASH_B; state_bit_idx++) {
    //     const auto state_bit = qs_state->load_witness_1_bit(witness_offset_bit_curr_state + state_bit_idx);
    //     last_round_sbox_output_bits[state_bit_idx] = state_bit[0];
    //     // state_secpar[state_bit_idx] = quicksilver_gfsecpar<QS>::combine_1_bit(state_bit.data());
    // }  
    // // witness_offset_bit_curr_state = 0;
    // // for (size_t state_idx = 0; state_idx < 4; state_idx++) {
    // //     last_round_sbox_output[state_idx] = quicksilver_gfsecpar<QS>::combine_128_bits(last_round_sbox_output_bits + witness_offset_bit_curr_state);
    // //     witness_offset_bit_curr_state += 128;
    // // }
    // // THE MAT MUL
    // // quicksilver_gfsecpar<QS> matmulres[VOLERAINHASH_B];
    // quicksilver_gf2<QS, P::OWF_CONSTS::DEG1> matmulres[VOLERAINHASH_B];
    // size_t round_idx = 7;
    // for (size_t matcol = 0; matcol < VOLERAINHASH_B; matcol++) {
    //     uint8_t zero = 0;
    //     quicksilver_gf2<QS, P::OWF_CONSTS::DEG1> qs_zero = quicksilver_gf2<QS, 0>(poly1::load(zero, 0), qs_state);
    //     matmulres[matcol] = qs_zero;
    //     for (size_t matrow = 0; matrow < VOLERAINHASH_B; matrow++) {
    //         // NOTE: This matrix mult is from the n - 1 th round!!!
    //         uint8_t* bit = (uint8_t*)&rain_matrix + (round_idx-1)*VOLERAINHASH_B*(VOLERAINHASH_B/8) + matcol*(VOLERAINHASH_B/8) 
    //                         + matrow/8;

    //         matmulres[matcol] += AND_GF2_CONST<QS>(last_round_sbox_output_bits[matrow], (*bit >> matrow%8) & 1);
    //     }
    // }

    // size_t matmulres_offset_bit = 0;
    // quicksilver_gfsecpar<QS, P::OWF_CONSTS::DEG1> state[4];
    // for (size_t state_idx = 0; state_idx < 4; state_idx++) {
    //     last_round_sbox_output[state_idx] = quicksilver_gfsecpar<QS>::combine_128_bits(matmulres + matmulres_offset_bit);
    //     matmulres_offset_bit += 128;
    // }

    // // Getting the first round input part
    // witness_offset_bit_curr_state = which_rainhash_witness_offset;
    // quicksilver_gfsecpar<QS, deg> in_state[4];
    // if (which_rainhash_witness_offset == 0) {

    //     const uint8_t* msg = (uint8_t*)&pk->msg;

    //     for (size_t state_idx = 0; state_idx < 1; state_idx++) {
    //         in_state[state_idx] = load_const_128_bits_and_combine(qs_state, msg);  // msg is 128 bits
    //     }
    //     for (size_t state_idx = 1; state_idx < 2; state_idx++) {
    //         in_state[state_idx] = qs_state->load_witness_128_bits_and_combine(witness_offset_bit_curr_state);
    //     }
    //     uint8_t capacity[32];
    //     memset(capacity, 0xff, 32);
    //     for (size_t state_idx = 2; state_idx < 4; state_idx++) {
    //         in_state[state_idx] = load_const_128_bits_and_combine(qs_state, capacity);
    //     }        
    // }
    // else {
    //     for (size_t state_idx = 0; state_idx < 4; state_idx++) {
    //         in_state[state_idx] = qs_state->load_witness_128_bits_and_combine(witness_offset_bit_curr_state);
    //         witness_offset_bit_curr_state += 128;
    //     }
    // }


    // qs_state->add_constraint(last_round_sbox_output[0] + hash_out[0]);
    // qs_state->add_constraint(last_round_sbox_output[1] + hash_out[1]);
    // qs_state->add_constraint(last_round_sbox_output[2] + hash_out[2]);
    // qs_state->add_constraint(last_round_sbox_output[3] + hash_out[3]);
    

    
}



#include "owf_proof_lowmc.inc"

// Mayo stuff
static inline uint8_t _mul_gf16(uint8_t a, uint8_t b) {

    size_t c = 0;
    while (b) {
        if (b & 1) {
            c ^= a;
        }
        a <<= 1;
        b >>= 1;
    }

    for(size_t i = 7; i > 3; i--) {
        if ((c >> i) & 1) {
            c ^= VOLEMAYO_MOD << (i - 4);
        }
    }
    return (uint8_t)c;
}
template <typename P>
static inline void _apply_e_p(uint64_t* data, size_t number_of_vecs){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;
    static constexpr size_t elements_in_last_uint = m - (uint64s_per_vec - 1) * 16;

    uint64_t last_mask = (((uint64_t)1) << (elements_in_last_uint * 4)) - 1;
    if (elements_in_last_uint == 16) {
        last_mask = 0xffffffffffffffff;
    }

    uint32_t tail_multiples[16];
    for (size_t i = 0; i < 16; i++) {
        tail_multiples[i] = 0;
        for (size_t j = 0; j < 4; j++) {
            tail_multiples[i] ^= _mul_gf16(i, VOLEMAYO_F_TAIL<P::secpar_v>[j]) << (j * 4);
        }
    }

    for (size_t idx = 0; idx < number_of_vecs; idx++) {
        char top_nibble = data[(idx+1) * uint64s_per_vec - 1] >> (((m-1) % 16) * 4);
        
        // shift up by 4 bits
        for (size_t i = uint64s_per_vec - 1; i > 0; i--) {
            data[idx * uint64s_per_vec + i] = (data[idx * uint64s_per_vec + i] << 4) |
                                              (data[idx * uint64s_per_vec + i - 1] >> 60);
        }
        data[idx * uint64s_per_vec] <<= 4;
        data[(idx+1) * uint64s_per_vec - 1] &= last_mask;
        // reduction mod f(X)
        data[idx * uint64s_per_vec] ^= tail_multiples[top_nibble];
    }
}
template <typename P>
static void _combineP1_P2_P3(const unsigned char * in, uint64_t *out){
    size_t i,j;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t v = VOLEMAYO_V<P::secpar_v>;
    static constexpr size_t o = VOLEMAYO_O<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = (m + 15) / 16;

    const unsigned char* P1 = in;
    const unsigned char* P2 = in + v*(v+1)/2*uint64s_per_vec*sizeof(uint64_t);
    const unsigned char* P3 = P2 + v*o*uint64s_per_vec*sizeof(uint64_t);

    memset(out, 0, n * (n + 1) / 2 * uint64s_per_vec * sizeof(uint64_t));

    // load and mix P1 and P2
    for (i = 0; i < v; i++) {
        for (j = i; j < v; j++) {
            memcpy((void *) out , P1, m / 2);
            P1 += uint64s_per_vec * sizeof(uint64_t);
            out += uint64s_per_vec;
        }
        for (; j < n; j++) {
            memcpy((void *) out , P2, m / 2);
            P2 += uint64s_per_vec * sizeof(uint64_t);
            out += uint64s_per_vec;
        }
    }
    // load P3
    memcpy((void *) out , P3, o*(o+1)/2*uint64s_per_vec*sizeof(uint64_t));
}
template <typename P>
static void sample_random_embedding(std::vector<poly_secpar<P::secpar_v>> &embedding_table, unsigned char * chall2){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    constexpr secpar S = P::secpar_v;
    static constexpr size_t security_bits = secpar_to_bits(S);

    
    embedding_table.resize(m*16);

    unsigned char randomness[m*sizeof(poly_secpar<S>)];

    hash_state hasher;

    // mu <- H_2^0(pk || msg)
    hasher.init(S);
    hasher.update(chall2, secpar_to_bits(S) / 4); // hash 2*lambda bits of chall2
    hasher.finalize(randomness, m*sizeof(poly_secpar<S>));

    const unsigned char (*gf4_in_gf_secpar)[security_bits/8]; 
    if constexpr (security_bits == 128) {
        gf4_in_gf_secpar = gf4_in_gf128;
    } else if constexpr (security_bits == 192) {
        gf4_in_gf_secpar = gf4_in_gf192;
    } else if constexpr (security_bits == 256) {
        gf4_in_gf_secpar = gf4_in_gf256;
    }

    poly_secpar<S> x   = poly_secpar<S>::load_dup(gf4_in_gf_secpar[0]);
    poly_secpar<S> xx  = poly_secpar<S>::load_dup(gf4_in_gf_secpar[1]);
    poly_secpar<S> xxx = poly_secpar<S>::load_dup(gf4_in_gf_secpar[2]);

    for (size_t i = 0; i < m; i++) {
        embedding_table[i*16 + 0] = poly_secpar<S>::set_zero();
        embedding_table[i*16 + 1] = poly_secpar<S>::load_dup(randomness + i*sizeof(poly_secpar<S>));
        embedding_table[i*16 + 2] = (x   * embedding_table[i*16 + 1]).template reduce_to<security_bits>();
        embedding_table[i*16 + 4] = (xx  * embedding_table[i*16 + 1]).template reduce_to<security_bits>();
        embedding_table[i*16 + 8] = (xxx * embedding_table[i*16 + 1]).template reduce_to<security_bits>();

        embedding_table[i*16 + 3] = embedding_table[i*16 + 2] + embedding_table[i*16 + 1];
        
        embedding_table[i*16 + 5] = embedding_table[i*16 + 4] + embedding_table[i*16 + 1];
        embedding_table[i*16 + 6] = embedding_table[i*16 + 4] + embedding_table[i*16 + 2];
        embedding_table[i*16 + 7] = embedding_table[i*16 + 4] + embedding_table[i*16 + 3];

        embedding_table[i*16 + 9]  = embedding_table[i*16 + 8] + embedding_table[i*16 + 1];
        embedding_table[i*16 + 10] = embedding_table[i*16 + 8] + embedding_table[i*16 + 2];
        embedding_table[i*16 + 11] = embedding_table[i*16 + 8] + embedding_table[i*16 + 3];
        embedding_table[i*16 + 12] = embedding_table[i*16 + 8] + embedding_table[i*16 + 4];
        embedding_table[i*16 + 13] = embedding_table[i*16 + 8] + embedding_table[i*16 + 5];
        embedding_table[i*16 + 14] = embedding_table[i*16 + 8] + embedding_table[i*16 + 6];
        embedding_table[i*16 + 15] = embedding_table[i*16 + 8] + embedding_table[i*16 + 7];
    }
}
template <typename P>
static void embed_gf16_vec(std::vector<poly_secpar<P::secpar_v>> embedding_table, const uint8_t* vec, poly_secpar<P::secpar_v> &poly){
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;

    poly = poly_secpar<P::secpar_v>::set_zero();
    for (size_t i = 0; i < m; i+=2)
    {
        unsigned char nibble_low = vec[i/2] & 0xf;
        unsigned char nibble_high = (vec[i/2] >> 4) & 0xf;
        poly += embedding_table[i * 16 + nibble_low];
        poly += embedding_table[(i+1) * 16 + nibble_high];
    }
}
template <typename QS, typename P, owf O>
static void
enc_constraints_mayo(QS* qs_state, const public_key<P>* pk, unsigned char * chal2)
{
    constexpr secpar S = QS::secpar_v;
    using OC = OWF_CONSTANTS<S, O>;

    // const uint8_t* hbytes = (uint8_t*)&pk->h;

    static constexpr size_t n = VOLEMAYO_N<P::secpar_v>;
    static constexpr size_t o = VOLEMAYO_O<P::secpar_v>;
    static constexpr size_t n_minus_o = VOLEMAYO_N_MINUS_O<P::secpar_v>;
    static constexpr size_t m = VOLEMAYO_M<P::secpar_v>;
    static constexpr size_t k = VOLEMAYO_K<P::secpar_v>;
    static constexpr size_t uint64s_per_vec = VOLEMAYO_u64s_per_m_vec<S>;

    // sample challenge embedding
    std::vector<poly_secpar<S>> embedding_table;
    sample_random_embedding<P>(embedding_table, chal2);

    // NOTE: Starting only after the keccak input, intermediate value witness


    // witness t is the output of keccak
    size_t witness_offset_bits_idx = NIBS_GADGET_2_OUT_OFF;

    constexpr size_t t_elem_size = VOLEMAYO_T_ELEM_SIZE<P::secpar_v>;
    auto t = qs_state->template const_gfsecpar_array<t_elem_size>();  
    for (size_t idx = 0; idx < t_elem_size; idx++) {
        t[idx] = qs_state->load_witness_4_bits_and_combine(witness_offset_bits_idx);
        witness_offset_bits_idx += 4;
    }

    quicksilver_gfsecpar<QS, 1> t_embedded(0, qs_state);
    for (int i = 0; i < m; i++)
    {
        t_embedded += embedding_table[16*i + 1] * t[i];
    }

    // witness s for mayo is stored after t
    witness_offset_bits_idx = VOLERAINHASH_WITNESS_SIZE_BITS<P::secpar_v>;
    
    constexpr size_t s_elem_size = VOLEMAYO_K<P::secpar_v> * VOLEMAYO_N<P::secpar_v>;
    std::vector<quicksilver_gfsecpar<QS, 1>> s(s_elem_size);
    for (size_t idx = 0; idx < s_elem_size; idx++) {
        s[idx] = qs_state->load_witness_4_bits_and_combine(witness_offset_bits_idx);
        witness_offset_bits_idx += 4;
    }

    // the trapdoor part
    quicksilver_gfsecpar<QS, 2> u(0,qs_state);
    poly_secpar<S> embedded_column;

    std::vector<uint64_t> _expanded_pk(VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<P::secpar_v>);
    uint64_t* expanded_pk = _expanded_pk.data();
    _combineP1_P2_P3<P>((unsigned char*) pk->mayo_expanded_pk, expanded_pk);

    std::vector<quicksilver_gfsecpar<QS, 1>> As(n);

    for (int i = 0; i < k; i++) {
        for (int j = k-1; j >= i; j--) {
            // multiply by 'E'
            if (i != 0 || j != k-1){
                _apply_e_p<P>(expanded_pk, n*(n+1)/2);
            }

            for (size_t a = 0 ; a<n; a++){
                As[a] = quicksilver_gfsecpar<QS, 1>(0, qs_state); 
            }

            // compute As = A * s_j         (if i == j)
            // or      As = (A + A^t) * s_j (if i != j)
            size_t ctr = 0;
            for (size_t a = 0; a < n; a++) {
                // skip i != j and a == b case
                ctr += (i != j);
                for (size_t b = a + (i != j); b < n; b++) {
                    embed_gf16_vec<P>(embedding_table, (unsigned char*) &expanded_pk[(ctr++) * uint64s_per_vec], embedded_column);
                
                    As[a] += embedded_column * s[j*n + b];
                    if (i != j){
                        As[b] += embedded_column * s[j*n + a];
                    }
                }    
            }

            // u += s_i * As
            for (size_t a = 0; a < n; a++) {
                u += As[a] * s[i * n + a];
            }
        }
    }

    // if constexpr (!QS::is_verifier) {
    //     size_t tmp_1 = 0;
    //     quicksilver_gfsecpar<QS, 2> a = u + t_embedded;
    //     memcpy(&tmp_1, &a.value().data, sizeof(tmp_1));
    //     std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //     memcpy(&tmp_1, (uint8_t*)&a.value().data + 8, sizeof(tmp_1));
    //     std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << tmp_1 << ", ";
    //     std::cout << "\n";
    // }

    qs_state->add_constraint(u + t_embedded);
}


// Cnsrts stuff
template <typename QS, typename P, owf O>
static void enc_constraints(QS* qs_state, const public_key<P>* pk, unsigned char * chall2)
{
    constexpr secpar S = QS::secpar_v;
    using OC = OWF_CONSTANTS<S, O>;


    qs_dbg_region = "lowmc";
    nibs_lowmc_constraints<QS, P>(qs_state, pk);

    qs_dbg_region = "rainA";
    // GadA: c = Rain(op | K | 0xff-fill). Lanes 0-1 (op, K) are witness,
    // lanes 2-3 are the constant fill.
    {
        const uint8_t* lc[4] = { nullptr, nullptr, RAIN_CAP16, RAIN_CAP16 };
        const size_t   lo[4] = { NIBS_GADA_OP_OFF,              // op
                                 NIBS_GADA_K_OFF,               // K copy
                                 0, 0 };
        enc_constraints_rainhash<QS, P, O>(qs_state, pk, NIBS_GADA_IN_OFF, lc, lo);
    }

    // Seams (lanes bound as GF(2^128) elements; combine is linear and
    // injective on 128 bits, so element equality == bitwise equality):
    //   K wires        == GadA in-block K lane          (1)
    //   GadA out[0:256] == Gad2 B1 c lanes              (2)
    //   r wires        == Gad2 B1 r lane                (1)
    qs_dbg_region = "seam";
    {
        auto k_lowmc = qs_state->load_witness_128_bits_and_combine(NIBS_K_BIT_OFF);
        auto k_gada  = qs_state->load_witness_128_bits_and_combine(NIBS_GADA_K_OFF);
        qs_state->add_constraint(k_lowmc + k_gada);

        for (size_t i = 0; i < 2; i++) {
            auto c_out = qs_state->load_witness_128_bits_and_combine(NIBS_GADA_OUT_OFF + 128*i);
            auto c_b1  = qs_state->load_witness_128_bits_and_combine(NIBS_GAD2_B1_BIT_OFF + 128*i);
            qs_state->add_constraint(c_out + c_b1);
        }

        auto r_lowmc = qs_state->load_witness_128_bits_and_combine(NIBS_R_BIT_OFF);
        auto r_b1    = qs_state->load_witness_128_bits_and_combine(NIBS_GAD2_B1_NONCE_OFF);
        qs_state->add_constraint(r_lowmc + r_b1);
    }

    qs_dbg_region = "rain1";
    // Rain gadget 2, block 1: h1 = Rain(c | r | salt[0..16])
    {
        const uint8_t* lc[4] = { nullptr, nullptr, nullptr, nullptr };
        const size_t   lo[4] = { NIBS_GAD2_B1_BIT_OFF,          // c lo
                                 NIBS_GAD2_B1_BIT_OFF + 128,    // c hi
                                 NIBS_GAD2_B1_NONCE_OFF,        // r
                                 NIBS_GAD2_B1_SALT_OFF };       // salt[0..16]
        enc_constraints_rainhash<QS, P, O>(qs_state, pk, NIBS_GAD2_B1_BIT_OFF, lc, lo);
    }

    // Chaining: B2 == h1 XOR ( salt[16..24] | 0xff-pad ).
    // Lanes 1-3 are pure pad, so they bind as field elements. Lane 0 mixes
    // the salt tail (prover-chosen, deliberately unbound) with 64 pad bits,
    // so those 64 bits are bound individually.
    qs_dbg_region = "chain";
    for (size_t i = 1; i < 4; i++) {
        auto b2  = qs_state->load_witness_128_bits_and_combine(NIBS_GAD2_B2_BIT_OFF + 128*i);
        auto h1  = qs_state->load_witness_128_bits_and_combine(NIBS_GAD2_H1_OFF     + 128*i);
        auto cap = load_const_128_bits_and_combine(qs_state, RAIN_CAP16);
        qs_state->add_constraint(b2 + h1 + cap);
    }
    for (size_t i = 64; i < 128; i++) {
        auto b2b = qs_state->get_witness_bit(NIBS_GAD2_B2_BIT_OFF + i);
        auto h1b = qs_state->get_witness_bit(NIBS_GAD2_H1_OFF     + i);
        qs_state->add_constraint(quicksilver_gfsecpar<QS, 2>(
            quicksilver_gfsecpar<QS, 1>(b2b) +
            quicksilver_gfsecpar<QS, 1>(h1b) +
            quicksilver_gfsecpar<QS, 1>(lowmc_const_bit(qs_state, 1))));
    }

    qs_dbg_region = "rain2";
    // Rain gadget 2, block 2: t = Rain(B2)
    {
        const uint8_t* lc[4] = { nullptr, nullptr, nullptr, nullptr };
        const size_t   lo[4] = { NIBS_GAD2_B2_BIT_OFF,       NIBS_GAD2_B2_BIT_OFF + 128,
                                 NIBS_GAD2_B2_BIT_OFF + 256, NIBS_GAD2_B2_BIT_OFF + 384 };
        enc_constraints_rainhash<QS, P, O>(qs_state, pk, NIBS_GAD2_B2_BIT_OFF, lc, lo);
    }

    // MAYO:  T*(s) = t, t read from gadget 2's out-block
    // (NIBS_GADGET_2_OUT_OFF), s from VOLERAINHASH_WITNESS_SIZE_BITS onward.
    qs_dbg_region = "mayo";
    enc_constraints_mayo<QS, P, O>(qs_state, pk, chall2);
}


template <typename P, bool verifier>
void owf_constraints(quicksilver_state<P::secpar_v, verifier, P::OWF_CONSTS::QS_DEGREE>* state,
                     const public_key<P>* pk, unsigned char* chall2)
{
    using QS = quicksilver_state<P::secpar_v, verifier, P::OWF_CONSTS::QS_DEGREE>;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;
    constexpr auto O = P::owf_v;

    qs_dbg_idx = 0;
    enc_constraints<QS, P, O>(state, pk, chall2);
#ifdef QS_DEBUG_CONSTRAINTS
    if constexpr (!verifier)
        fprintf(stderr, "constraints emitted: %zu (declared: %zu)\n",
                qs_dbg_idx, (size_t)P::OWF_CONSTS::OWF_NUM_CONSTRAINTS);
#endif
}


} // namespace faest

#endif
