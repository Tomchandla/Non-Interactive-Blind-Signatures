#ifndef FAEST_H
#define FAEST_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif



    void rain_hash_512_7_c(uint8_t* output, size_t  outlen,const uint8_t* input, size_t inlen);

    
    // ------ v1 ------

    // getters for the parameters
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
                                               size_t *s_size);
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
                                               size_t *s_size);

    // v2 128
    // pkR = c = trunc_256( RainHash( op | K | 0xff-fill ) )
    void nibs_rain_pkr(const uint8_t* op, const uint8_t* k, uint8_t* pkr);

    bool rainhash_then_mayo128sv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, uint8_t* salt, uint8_t* additional_r);

    bool rainhash_then_mayo128fv1_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, uint8_t* salt, uint8_t* additional_r);

    bool rainhash_then_mayo128sv1_verify(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* additional_r);

    bool rainhash_then_mayo128fv1_verify(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* additional_r);

                
    // ------ v2 ------

    // getters for the parameters
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
                                               size_t *s_size);
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
                                               size_t *s_size);

    // v2 128
    bool rainhash_then_mayo128sv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, uint8_t* salt, uint8_t* additional_r);

    bool rainhash_then_mayo128fv2_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc_qs, uint8_t* rain_mat_qs,
                uint8_t* s, uint8_t* skr_ptr, uint8_t* open, uint8_t* nonce, uint8_t* salt, uint8_t* additional_r);

    bool rainhash_then_mayo128sv2_verify(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* additional_r);

    bool rainhash_then_mayo128fv2_verify(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* additional_r);


#ifdef __cplusplus
}
#endif

#endif
