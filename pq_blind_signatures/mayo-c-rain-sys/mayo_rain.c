// SPDX-License-Identifier: Apache-2.0

#include <mem.h>
#include <mayo.h>
#include <randombytes.h>
#include <aes_ctr.h>
#include <arithmetic.h>
#include <simple_arithmetic.h>
#include <fips202.h>
#include <stdlib.h>
#include <string.h>
#include <stdalign.h>
#include <mayo.c>
#define WITH_RAINHASH
#include <faest.h>

#include <stdio.h>

int mayo_rain_sign_signature_fixed_length_input(const mayo_params_t *p, unsigned char *sig,
              size_t *siglen, const unsigned char *m,
              size_t mlen, const unsigned char *csk) {
    int ret = MAYO_OK;
    unsigned char tenc[M_BYTES_MAX], t[M_MAX]; // no secret data
    unsigned char y[M_MAX];                    // secret data
    unsigned char salt[SALT_BYTES_MAX];        // not secret data
    unsigned char V[K_MAX * V_BYTES_MAX + R_BYTES_MAX], Vdec[V_MAX * K_MAX];                 // secret data
    unsigned char A[((M_MAX+7)/8*8) * (K_MAX * O_MAX + 1)] = { 0 };   // secret data
    unsigned char x[K_MAX * N_MAX];                       // not secret data
    unsigned char r[K_MAX * O_MAX + 1] = { 0 };           // secret data
    unsigned char s[K_MAX * N_MAX];                       // not secret data
    const unsigned char *seed_sk;
    alignas(32) sk_t sk;                    // secret data
    unsigned char Ox[V_MAX];        // secret data
    // unsigned char tmp[DIGEST_BYTES_MAX + SALT_BYTES_MAX];
    // therefore no overflow can occur
    // unsigned char tmp[DIGEST_BYTES_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX + 1];
    unsigned char tmp[DIGEST_BYTES_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX + 1];
    // maximum input size for rain
    unsigned char tmp_t_rain_input[64] = {0};
    memset(tmp_t_rain_input, 0xff, 64); // changed this from 0x00 becuase of the zero s-box problem
    unsigned char *ctrbyte;
    unsigned char *vi;

    const int param_m = PARAM_m(p);
    const int param_n = PARAM_n(p);
    const int param_o = PARAM_o(p);
    const int param_k = PARAM_k(p);
    const int param_v = PARAM_v(p);
    const int param_m_bytes = PARAM_m_bytes(p);
    const int param_v_bytes = PARAM_v_bytes(p);
    const int param_r_bytes = PARAM_r_bytes(p);
    const int param_sig_bytes = PARAM_sig_bytes(p);
    const int param_A_cols = PARAM_A_cols(p);
    const int param_digest_bytes = PARAM_digest_bytes(p);
    const int param_sk_seed_bytes = PARAM_sk_seed_bytes(p);
    const int param_salt_bytes = PARAM_salt_bytes(p);

    ret = mayo_expand_sk(p, csk, &sk);
    if (ret != MAYO_OK) {
        goto err;
    }

    seed_sk = csk;


    // hash message
    // shake256(tmp, param_digest_bytes, m, mlen);
    if (mlen != (size_t)param_digest_bytes)
    {
        goto err;
    }
    memcpy(tmp, m, param_digest_bytes);
    memcpy(tmp_t_rain_input, m, param_digest_bytes);

    uint64_t *P1 = sk.p;
    uint64_t *L  = P1 + PARAM_P1_limbs(p);
    uint64_t Mtmp[K_MAX * O_MAX * M_VEC_LIMBS_MAX] = {0};

#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < PARAM_P1_limbs(p); ++i) {
        P1[i] = BSWAP64(P1[i]);
    }
    for (int i = 0; i < PARAM_P2_limbs(p); ++i) {
        L[i] = BSWAP64(L[i]);
    }
#endif

    // choose the randomizer
    #if defined(PQM4) || defined(HAVE_RANDOMBYTES_NORETVAL)
    randombytes(tmp + param_digest_bytes, param_salt_bytes);
    #else
    if (randombytes(tmp + param_digest_bytes, param_salt_bytes) != MAYO_OK) {
        ret = MAYO_ERR;
        goto err;
    }
    #endif

    // hashing to salt
    memcpy(tmp + param_digest_bytes + param_salt_bytes, seed_sk,
           param_sk_seed_bytes);
    shake256(salt, param_salt_bytes, tmp,
             param_digest_bytes + param_salt_bytes + param_sk_seed_bytes);

#ifdef ENABLE_CT_TESTING
    VALGRIND_MAKE_MEM_DEFINED(salt, SALT_BYTES_MAX); // Salt is not secret
#endif

    // hashing to t
    memcpy(tmp + param_digest_bytes, salt, param_salt_bytes);
    memcpy(tmp_t_rain_input + param_digest_bytes, salt, param_salt_bytes);
    ctrbyte = tmp + param_digest_bytes + param_salt_bytes + param_sk_seed_bytes;

    // --- This is the only part where we replace shake with rain ---
    rain_hash_512_7_c(tenc, param_m_bytes, tmp_t_rain_input, 64);
    // ---

    decode(tenc, t, param_m); // may not be necessary

    for (int ctr = 0; ctr <= 255; ++ctr) {
        *ctrbyte = (unsigned char)ctr;

        shake256(V, param_k * param_v_bytes + param_r_bytes, tmp,
                 param_digest_bytes + param_salt_bytes + param_sk_seed_bytes + 1);

        // decode the v_i vectors
        for (int i = 0; i <= param_k - 1; ++i) {
            decode(V + i * param_v_bytes, Vdec + i * param_v, param_v);
        }

        // compute M_i matrices and all v_i*P1*v_j
        compute_M_and_VPV(p, Vdec, L, P1, Mtmp, (uint64_t*) A);

        compute_rhs(p, (uint64_t*) A, t, y);
        compute_A(p, Mtmp, A);

        for (int i = 0; i < param_m; i++)
        {
            A[(1+i)*(param_k*param_o + 1) - 1] = 0;
        }

        decode(V + param_k * param_v_bytes, r,
               param_k *
               param_o);

        if (sample_solution(p, A, y, r, x, param_k, param_o, param_m, param_A_cols)) {
            break;
        } else {
            memset(Mtmp, 0, sizeof(Mtmp));
            memset(A, 0, sizeof(A));
        }
    }

    for (int i = 0; i <= param_k - 1; ++i) {
        vi = Vdec + i * (param_n - param_o);
        mat_mul(sk.O, x + i * param_o, Ox, param_o, param_n - param_o, 1);
        mat_add(vi, Ox, s + i * param_n, param_n - param_o, 1);
        memcpy(s + i * param_n + (param_n - param_o), x + i * param_o, param_o);
    }
    encode(s, sig, param_n * param_k);

    memcpy(sig + param_sig_bytes - param_salt_bytes, salt, param_salt_bytes);
    *siglen = param_sig_bytes;

err:
    mayo_secure_clear(V, sizeof(V));
    mayo_secure_clear(Vdec, sizeof(Vdec));
    mayo_secure_clear(A, sizeof(A));
    mayo_secure_clear(r, sizeof(r));
    mayo_secure_clear(sk.O, sizeof(sk.O));
    mayo_secure_clear(&sk, sizeof(sk_t));
    mayo_secure_clear(Ox, sizeof(Ox));
    mayo_secure_clear(tmp, sizeof(tmp));
    mayo_secure_clear(Mtmp, sizeof(Mtmp));
    return ret;
};

int mayo_rain_sign_fixed_length_input(const mayo_params_t *p, unsigned char *s,
              size_t *slen, const unsigned char *m,
              size_t mlen, const unsigned char *csk) {
    int ret = MAYO_OK;
    const int param_sig_bytes = PARAM_sig_bytes(p);
    size_t siglen;
    ret = mayo_rain_sign_signature_fixed_length_input(p, s, &siglen, m, mlen, csk);
    if (ret != MAYO_OK || siglen != (size_t) param_sig_bytes){
        memset(s, 0, siglen);
        goto err;
    }

    *slen = siglen;
err:
    return ret;
}


int mayo_rain_verify_fixed_length_input(const mayo_params_t *p, const unsigned char *m,
                size_t mlen, const unsigned char *sig,
                const unsigned char *cpk) {
    unsigned char tEnc[M_BYTES_MAX];
    unsigned char t[M_MAX];
    unsigned char y[2 * M_MAX] = {0}; // extra space for reduction mod f(X)
    unsigned char s[K_MAX * N_MAX];
    uint64_t pk[P1_LIMBS_MAX + P2_LIMBS_MAX + P3_LIMBS_MAX] = {0};
    unsigned char tmp[64] = {0};
    memset(tmp, 0xff, 64); // changed this from 0x00 becuase of the zero s-box problem

    const int param_m = PARAM_m(p);
    const int param_n = PARAM_n(p);
    const int param_k = PARAM_k(p);
    const int param_m_bytes = PARAM_m_bytes(p);
    const int param_sig_bytes = PARAM_sig_bytes(p);
    const int param_digest_bytes = PARAM_digest_bytes(p);
    const int param_salt_bytes = PARAM_salt_bytes(p);

    int ret = mayo_expand_pk(p, cpk, pk);
    if (ret != MAYO_OK) {
        return MAYO_ERR;
    }

    uint64_t *P1 = pk;
    uint64_t *P2 = P1 + PARAM_P1_limbs(p);
    uint64_t *P3 = P2 + PARAM_P2_limbs(p);

#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < PARAM_P1_limbs(p); ++i) {
        P1[i] = BSWAP64(P1[i]);
    }
    for (int i = 0; i < PARAM_P2_limbs(p); ++i) {
        P2[i] = BSWAP64(P2[i]);
    }
    for (int i = 0; i < PARAM_P3_limbs(p); ++i) {
        P3[i] = BSWAP64(P3[i]);
    }
#endif

    // hash m
    // shake256(tmp, param_digest_bytes, m, mlen);
    if (mlen != (size_t)param_digest_bytes)
    {
        return MAYO_ERR;
    }
    memcpy(tmp, m, param_digest_bytes);

    // compute t
    memcpy(tmp + param_digest_bytes, sig + param_sig_bytes - param_salt_bytes,
           param_salt_bytes);
    // --- This is the only modification where shake256 is replaced with rain 
    rain_hash_512_7_c(tEnc, param_m_bytes, tmp, 64);

    // printf("rain input\n");
    // for (size_t i = 0; i < 64; i++) {
    //     printf("%02x ", tmp[i]);
    // }
    // printf("\n");

    // printf("rain output\n");
    // for (size_t i = 0; i < 64; i++) {
    //     printf("%02x ", tEnc[i]);
    // }
    // printf("\n");

    // ---
    decode(tEnc, t, param_m);

    // decode s
    decode(sig, s, param_k * param_n);

    eval_public_map(p, s, P1, P2, P3, y);

    if (memcmp(y, t, param_m) == 0) {
        return MAYO_OK; // good signature
    }
    return MAYO_ERR; // bad signature
}
