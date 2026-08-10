
#ifndef mayo_rain_h
#define mayo_rain_h

#include <stdint.h>
#include <stdlib.h>
#include "mayo.h"

// headers for the self-defined functions
#define mayo_lowmc_sign_fixed_length_input MAYO_NAMESPACE(mayo_lowmc_sign_fixed_length_input)

#define mayo_rain_sign_fixed_length_input MAYO_NAMESPACE(mayo_rain_sign_fixed_length_input)
int mayo_rain_sign_fixed_length_input(const mayo_params_t *p, unsigned char *s,
              size_t *slen, const unsigned char *m,
              size_t mlen, const unsigned char *csk);
           
#define mayo_rain_verify_fixed_length_input MAYO_NAMESPACE(mayo_rain_verify_fixed_length_input)
int mayo_rain_verify_fixed_length_input(const mayo_params_t *p, const unsigned char *m,
                size_t mlen, const unsigned char *sig,
                const unsigned char *cpk);

void rain_hash_512_7_c(uint8_t* output, size_t  outlen,const uint8_t* input, size_t inlen);
#endif
