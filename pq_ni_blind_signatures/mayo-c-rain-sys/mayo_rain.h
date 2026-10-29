#ifndef mayo_rain_h
#define mayo_rain_h

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "mayo.h"

// MAYO signing and verification for NIBS presignatures. They differ from
// Mayo.sign() and Mayo.verify() of the MAYO spec only in how the target is
// derived.

/**
 * NIST level of a MAYO parameter set, as used by NIBS.
 * NIBS uses MAYO_1, MAYO_3 and MAYO_5 at levels 1, 3 and 5. The level also
 * selects the Rain mode T that derives the target.
 *
 * @param[in] p Mayo parameter set
 * @return int 1, 3 or 5, or 0 if the parameter set is not used by NIBS (e.g. MAYO_2)
 */
#define mayo_nibs_level MAYO_NAMESPACE(mayo_nibs_level)
int mayo_nibs_level(const mayo_params_t *p);

/**
 * MAYO presignature on the fixed-length NIBS message M = r || pk_R.
 *
 * The implementation performs Mayo.expandSK() + Mayo.sign() of the MAYO spec,
 * but without hashing M to a message digest and the vinegar variables are derived 
 * from SHAKE256(M || salt || seed_sk || ctr). The signature s is a preimage of t 
 * under the public map P*. Keys provided is a compacted secret key.
 * The caller is responsible to allocate PARAM_sig_bytes(p) bytes for sig.
 *
 * @param[in] p Mayo parameter set (MAYO_1, MAYO_3 or MAYO_5)
 * @param[out] sig Presignature s || salt
 * @param[out] siglen Pointer to the length of sig (PARAM_sig_bytes(p) on success)
 * @param[in] m Message M = r || pk_R (fixed length per level and framework)
 * @param[in] mlen Length of m in bytes (at most 128)
 * @param[in] csk Compacted secret key
 * @return int MAYO_OK (0) on success, MAYO_ERR (1) if the parameter set or
 *         message length is not supported or no preimage was found
 */
#define mayo_nibs_sign MAYO_NAMESPACE(mayo_nibs_sign)
int mayo_nibs_sign(const mayo_params_t *p, unsigned char *sig, size_t *siglen,
                   const unsigned char *m, size_t mlen, const unsigned char *csk);

/**
 * Verify a MAYO presignature on the fixed-length NIBS message M = r || pk_R.
 *
 * The implementation performs Mayo.verify(), but without hashing M to a 
 * message digest: it recomputes t = T(M || salt) with the Rain
 * mode, using the salt at the end of sig, and checks that P*(s) = t.
 * The receiver runs this in Obtain before proving anything; the same check is
 * then proven in zero knowledge by the MAYO gadget of the circuit.
 *
 * @param[in] p Mayo parameter set (MAYO_1, MAYO_3 or MAYO_5)
 * @param[in] m Message M = r || pk_R (fixed length per level and framework)
 * @param[in] mlen Length of m in bytes (at most 128)
 * @param[in] sig Presignature s || salt
 * @param[in] siglen Length of sig (must be PARAM_sig_bytes(p))
 * @param[in] cpk Compacted public key
 * @return int MAYO_OK (0) if verification succeeded, MAYO_ERR (1) otherwise
 */
#define mayo_nibs_verify MAYO_NAMESPACE(mayo_nibs_verify)
int mayo_nibs_verify(const mayo_params_t *p, const unsigned char *m, size_t mlen,
                     const unsigned char *sig, size_t siglen, const unsigned char *cpk);

#endif
