#ifndef mayo_rain_h
#define mayo_rain_h

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "mayo.h"

// NIST level (1, 3, 5) of a MAYO parameter set as used by NIBS; 0 otherwise.
#define mayo_nibs_level MAYO_NAMESPACE(mayo_nibs_level)
int mayo_nibs_level(const mayo_params_t *p);

// Presignature on M = r || pk_R: MAYO with the Rain target T(M || salt);
// the output is s || salt.
#define mayo_nibs_sign MAYO_NAMESPACE(mayo_nibs_sign)
int mayo_nibs_sign(const mayo_params_t *p, unsigned char *sig, size_t *siglen,
                   const unsigned char *m, size_t mlen, const unsigned char *csk);

#define mayo_nibs_verify MAYO_NAMESPACE(mayo_nibs_verify)
int mayo_nibs_verify(const mayo_params_t *p, const unsigned char *m, size_t mlen,
                     const unsigned char *sig, size_t siglen, const unsigned char *cpk);

#endif
