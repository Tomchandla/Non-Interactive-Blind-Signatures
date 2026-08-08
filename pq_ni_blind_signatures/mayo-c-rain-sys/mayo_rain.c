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
#include <faest.h>

#include <stdio.h>

// pkR(32) || nonce(16).
#define NIBS_MSG_BYTES 48

static void nibs_rain2_target(unsigned char *tenc, size_t tenc_len,
                              const unsigned char *m,
                              const unsigned char *salt, int salt_bytes) {
    unsigned char b1[64];
    unsigned char h1[64];
    unsigned char b2[64];

    // B1 = m || salt[0..16]
    memcpy(b1, m, NIBS_MSG_BYTES);
    memcpy(b1 + NIBS_MSG_BYTES, salt, 64 - NIBS_MSG_BYTES);

    rain_hash_512_7_c(h1, 64, b1, 64);

    // B2 = salt[16..salt_bytes] || 0xff-pad, chained with h1
    memset(b2, 0xff, 64);
    memcpy(b2, salt + (64 - NIBS_MSG_BYTES),
           (size_t)salt_bytes - (64 - NIBS_MSG_BYTES));
    for (int i = 0; i < 64; i++) {
        b2[i] ^= h1[i];
    }

    rain_hash_512_7_c(tenc, tenc_len, b2, 64);
}

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
    // salt/V derivation buffer: message(48) || salt || seed_sk || ctr
    unsigned char tmp[NIBS_MSG_BYTES + SALT_BYTES_MAX + SK_SEED_BYTES_MAX + 1];
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
    const int param_sk_seed_bytes = PARAM_sk_seed_bytes(p);
    const int param_salt_bytes = PARAM_salt_bytes(p);

    ret = mayo_expand_sk(p, csk, &sk);
    if (ret != MAYO_OK) {
        goto err;
    }

    seed_sk = csk;

    // The NIBS message is pkR || nonce, fixed at 48 bytes
    if (mlen != (size_t)NIBS_MSG_BYTES)
    {
        goto err;
    }
    memcpy(tmp, m, NIBS_MSG_BYTES);

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
    randombytes(tmp + NIBS_MSG_BYTES, param_salt_bytes);
    #else
    if (randombytes(tmp + NIBS_MSG_BYTES, param_salt_bytes) != MAYO_OK) {
        ret = MAYO_ERR;
        goto err;
    }
    #endif

    // hashing to salt
    memcpy(tmp + NIBS_MSG_BYTES + param_salt_bytes, seed_sk,
           param_sk_seed_bytes);
    shake256(salt, param_salt_bytes, tmp,
             NIBS_MSG_BYTES + param_salt_bytes + param_sk_seed_bytes);

#ifdef ENABLE_CT_TESTING
    VALGRIND_MAKE_MEM_DEFINED(salt, SALT_BYTES_MAX); // Salt is not secret
#endif

    // hashing to t
    memcpy(tmp + NIBS_MSG_BYTES, salt, param_salt_bytes);
    ctrbyte = tmp + NIBS_MSG_BYTES + param_salt_bytes + param_sk_seed_bytes;

    // --- This is the only part where we replace shake with rain ---
    // t = Rain2( pkR || nonce || salt || 0xff-pad ), two blocks
    nibs_rain2_target(tenc, param_m_bytes, m, salt, param_salt_bytes);
    // ---

    decode(tenc, t, param_m); // may not be necessary

    for (int ctr = 0; ctr <= 255; ++ctr) {
        *ctrbyte = (unsigned char)ctr;

        shake256(V, param_k * param_v_bytes + param_r_bytes, tmp,
                 NIBS_MSG_BYTES + param_salt_bytes + param_sk_seed_bytes + 1);

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

    const int param_m = PARAM_m(p);
    const int param_n = PARAM_n(p);
    const int param_k = PARAM_k(p);
    const int param_m_bytes = PARAM_m_bytes(p);
    const int param_sig_bytes = PARAM_sig_bytes(p);
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

    // check if the NIBS message is fixed at 48 bytes
    if (mlen != (size_t)NIBS_MSG_BYTES)
    {
        return MAYO_ERR;
    }

    // compute new NIBS t (this calls rain_hash_512_7_c)
    nibs_rain2_target(tEnc, param_m_bytes, m,
                      sig + param_sig_bytes - param_salt_bytes,
                      param_salt_bytes);
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
