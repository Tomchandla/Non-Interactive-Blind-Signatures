// SPDX-License-Identifier: Apache-2.0

#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>

void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void shake256_w(uint8_t* witness, const uint8_t *input, size_t inlen);
int shake256(unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen);

#endif

