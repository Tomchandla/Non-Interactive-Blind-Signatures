
#ifndef mayo_without_hashing_h
#define mayo_without_hashing_h

#include <stdint.h>
#include <stdlib.h>
#include "mayo.h"

// headers for the self-defined functions

/**
 * MAYO signature generation, but without hashing.
 *
 * The implementation performs Mayo.expandSK() + Mayo.sign() in the Mayo spec, but without hashing.
 * Keys provided is a compacted secret keys.
 * The caller is responsible to allocate sufficient memory to hold sm.
 *
 * @param[in] p Mayo parameter set
 * @param[out] s Signature
 * @param[out] slen Pointer to the length of s
 * @param[in] t Hash of the message to be signed
 * @param[in] tlen Length of t
 * @param[in] sk Compacted secret key
 * @return int status code
 */
#define mayo_sign_without_hashing MAYO_NAMESPACE(mayo_sign_without_hashing)
int mayo_sign_without_hashing(const mayo_params_t *p, unsigned char *s,
                              size_t *slen, const unsigned char *t,
                              size_t tlen, const unsigned char *csk);

/**
 * Mayo verify signature, but without hashing.
 *
 * The implementation performs Mayo.verify(). If the signature verification succeeded, returns 0, otherwise 1.
 * Keys provided is a compact public key.
 *
 * @param[in] p Mayo parameter set
 * @param[in] t Hash of the message for which the signature is verified
 * @param[in] tlen Length of t
 * @param[in] sig Signature
 * @param[in] pk Compacted public key
 * @return int 0 if verification succeeded, 1 otherwise.
 */
#define mayo_verify_without_hashing MAYO_NAMESPACE(mayo_verify_without_hashing)
int mayo_verify_without_hashing(const mayo_params_t *p, const unsigned char *t,
                                size_t tlen, const unsigned char *sig,
                                const unsigned char *cpk);

/**
 * MAYO signature generation, but without hashing to message digest.
 *
 * The implementation performs Mayo.expandSK() + Mayo.sign() in the Mayo spec, but without hashing.
 * Keys provided is a compacted secret keys.
 * The caller is responsible to allocate sufficient memory to hold sm.
 *
 * @param[in] p Mayo parameter set
 * @param[out] s Signature + Salt
 * @param[out] slen Pointer to the length of s
 * @param[in] m M_Digest of the message (i.e. fixed length)
 * @param[in] mlen Length of t (must be M_Digest_Bytes)
 * @param[in] sk Compacted secret key
 * @return int status code
 */
#define mayo_sign_fixed_length_input MAYO_NAMESPACE(mayo_sign_fixed_length_input)
int mayo_sign_fixed_length_input(const mayo_params_t *p, unsigned char *s,
              size_t *slen, const unsigned char *m,
              size_t mlen, const unsigned char *csk);
           
/**
 * Mayo verify signature, but without hashing.
 *
 * The implementation performs Mayo.verify(). If the signature verification succeeded, returns 0, otherwise 1.
 * Keys provided is a compact public key.
 *
 * @param[in] p Mayo parameter set
 * @param[in] m M_Digest of the message (i.e. fixed length)
 * @param[in] mlen Length of t (must be M_Digest_Bytes)
 * @param[in] sig Signature
 * @param[in] pk Compacted public key
 * @return int 0 if verification succeeded, 1 otherwise.
 */
#define mayo_verify_fixed_length_input MAYO_NAMESPACE(mayo_verify_fixed_length_input)
int mayo_verify_fixed_length_input(const mayo_params_t *p, const unsigned char *m,
                size_t mlen, const unsigned char *sig,
                const unsigned char *cpk);


#endif