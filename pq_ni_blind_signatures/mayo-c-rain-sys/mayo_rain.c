// SPDX-License-Identifier: Apache-2.0
// Modified for multiple chains of Rain to replace shake proof.

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
#include "mayo_rain.h"

#define NIBS_MSG_MAX 128 // r (<= 32) and pk_R (<= 64)

int mayo_nibs_level(const mayo_params_t *p)
{
    switch (PARAM_m(p))
    {
    case 78: return 1;  // MAYO_1
    case 108: return 3; // MAYO_3
    case 142: return 5; // MAYO_5
    default: return 0;
    }
}

// tenc = T(M || salt), m_bytes bytes.
static int nibs_target_enc(const mayo_params_t *p, unsigned char *tenc, const unsigned char *m,
                           size_t mlen, const unsigned char *salt, size_t salt_len)
{
    unsigned char buf[NIBS_MSG_MAX + SALT_BYTES_MAX];
    const int level = mayo_nibs_level(p);
    if (level == 0 || mlen > NIBS_MSG_MAX)
        return MAYO_ERR;
    memcpy(buf, m, mlen);
    memcpy(buf + mlen, salt, salt_len);
    nibs_target((unsigned)level, buf, mlen + salt_len, tenc, (size_t)PARAM_m_bytes(p));
    return MAYO_OK;
}

// Preimage sampling for target tenc. vseed (vseed_len bytes) seeds the
// vinegar/randomness derivation V = SHAKE256(vseed || ctr).
static int nibs_sample_preimage(const mayo_params_t *p, sk_t *sk, const unsigned char *tenc,
                                unsigned char *vseed, size_t vseed_len, unsigned char *sig)
{
    unsigned char t[M_MAX];
    unsigned char y[M_MAX];
    unsigned char V[K_MAX * V_BYTES_MAX + R_BYTES_MAX], Vdec[V_MAX * K_MAX];
    unsigned char A[((M_MAX + 7) / 8 * 8) * (K_MAX * O_MAX + 1)] = {0};
    unsigned char x[K_MAX * N_MAX];
    unsigned char r[K_MAX * O_MAX + 1] = {0};
    unsigned char s[K_MAX * N_MAX];
    unsigned char Ox[V_MAX];
    unsigned char *vi;
    uint64_t Mtmp[K_MAX * O_MAX * M_VEC_LIMBS_MAX] = {0};
    int found = 0;

    const int param_m = PARAM_m(p);
    const int param_n = PARAM_n(p);
    const int param_o = PARAM_o(p);
    const int param_k = PARAM_k(p);
    const int param_v = PARAM_v(p);
    const int param_v_bytes = PARAM_v_bytes(p);
    const int param_r_bytes = PARAM_r_bytes(p);
    const int param_A_cols = PARAM_A_cols(p);

    uint64_t *P1 = sk->p;
    uint64_t *L = P1 + PARAM_P1_limbs(p);
#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < PARAM_P1_limbs(p); ++i)
        P1[i] = BSWAP64(P1[i]);
    for (int i = 0; i < PARAM_P2_limbs(p); ++i)
        L[i] = BSWAP64(L[i]);
#endif

    decode(tenc, t, param_m);
    unsigned char *ctrbyte = vseed + vseed_len - 1;

    for (int ctr = 0; ctr <= 255; ++ctr)
    {
        *ctrbyte = (unsigned char)ctr;
        shake256(V, param_k * param_v_bytes + param_r_bytes, vseed, vseed_len);
        for (int i = 0; i <= param_k - 1; ++i)
            decode(V + i * param_v_bytes, Vdec + i * param_v, param_v);
        compute_M_and_VPV(p, Vdec, L, P1, Mtmp, (uint64_t *)A);
        compute_rhs(p, (uint64_t *)A, t, y);
        compute_A(p, Mtmp, A);
        for (int i = 0; i < param_m; i++)
            A[(1 + i) * (param_k * param_o + 1) - 1] = 0;
        decode(V + param_k * param_v_bytes, r, param_k * param_o);
        if (sample_solution(p, A, y, r, x, param_k, param_o, param_m, param_A_cols))
        {
            found = 1;
            break;
        }
        memset(Mtmp, 0, sizeof(Mtmp));
        memset(A, 0, sizeof(A));
    }

    if (found)
    {
        for (int i = 0; i <= param_k - 1; ++i)
        {
            vi = Vdec + i * (param_n - param_o);
            mat_mul(sk->O, x + i * param_o, Ox, param_o, param_n - param_o, 1);
            mat_add(vi, Ox, s + i * param_n, param_n - param_o, 1);
            memcpy(s + i * param_n + (param_n - param_o), x + i * param_o, param_o);
        }
        encode(s, sig, param_n * param_k);
    }

    mayo_secure_clear(V, sizeof(V));
    mayo_secure_clear(Vdec, sizeof(Vdec));
    mayo_secure_clear(A, sizeof(A));
    mayo_secure_clear(r, sizeof(r));
    mayo_secure_clear(Ox, sizeof(Ox));
    mayo_secure_clear(Mtmp, sizeof(Mtmp));
    mayo_secure_clear(y, sizeof(y));
    return found ? MAYO_OK : MAYO_ERR;
}

int mayo_nibs_sign(const mayo_params_t *p, unsigned char *sig, size_t *siglen,
                   const unsigned char *m, size_t mlen, const unsigned char *csk)
{
    int ret;
    alignas(32) sk_t sk;
    unsigned char tenc[M_BYTES_MAX];
    unsigned char salt[SALT_BYTES_MAX];
    unsigned char tmp[NIBS_MSG_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX];
    // vseed buffer: M || salt || seed_sk || ctr
    unsigned char vseed[NIBS_MSG_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX + 1];
    const int param_salt_bytes = PARAM_salt_bytes(p);
    const int param_sk_seed_bytes = PARAM_sk_seed_bytes(p);
    const int s_bytes = PARAM_sig_bytes(p) - param_salt_bytes;
    size_t vlen;

    if (mlen > NIBS_MSG_MAX)
        return MAYO_ERR;
    ret = mayo_expand_sk(p, csk, &sk);
    if (ret != MAYO_OK)
        goto err;

    // salt = shake256(M || R || seed_sk)
    memcpy(tmp, m, mlen);
    if (randombytes(tmp + mlen, param_salt_bytes) != MAYO_OK)
    {
        ret = MAYO_ERR;
        goto err;
    }
    memcpy(tmp + mlen + param_salt_bytes, csk, param_sk_seed_bytes);
    shake256(salt, param_salt_bytes, tmp, mlen + param_salt_bytes + param_sk_seed_bytes);

    ret = nibs_target_enc(p, tenc, m, mlen, salt, param_salt_bytes);
    if (ret != MAYO_OK)
        goto err;
    // V = shake256(M || salt || seed_sk || ctr)
    memcpy(vseed, m, mlen);
    memcpy(vseed + mlen, salt, param_salt_bytes);
    memcpy(vseed + mlen + param_salt_bytes, csk, param_sk_seed_bytes);
    vlen = mlen + param_salt_bytes + param_sk_seed_bytes + 1;
    ret = nibs_sample_preimage(p, &sk, tenc, vseed, vlen, sig);
    if (ret == MAYO_OK)
    {
        memcpy(sig + s_bytes, salt, param_salt_bytes);
        *siglen = (size_t)PARAM_sig_bytes(p);
    }

err:
    mayo_secure_clear(&sk, sizeof(sk_t));
    mayo_secure_clear(tmp, sizeof(tmp));
    mayo_secure_clear(vseed, sizeof(vseed));
    return ret;
}

int mayo_nibs_verify(const mayo_params_t *p, const unsigned char *m, size_t mlen,
                     const unsigned char *sig, size_t siglen, const unsigned char *cpk)
{
    unsigned char tEnc[M_BYTES_MAX];
    unsigned char t[M_MAX];
    unsigned char y[2 * M_MAX] = {0};
    unsigned char s[K_MAX * N_MAX];
    uint64_t pk[P1_LIMBS_MAX + P2_LIMBS_MAX + P3_LIMBS_MAX] = {0};
    const int param_m = PARAM_m(p);
    const int param_n = PARAM_n(p);
    const int param_k = PARAM_k(p);
    const int param_salt_bytes = PARAM_salt_bytes(p);
    const size_t s_bytes = (size_t)(PARAM_sig_bytes(p) - param_salt_bytes);

    if (siglen != (size_t)PARAM_sig_bytes(p))
        return MAYO_ERR;
    if (mayo_expand_pk(p, cpk, pk) != MAYO_OK)
        return MAYO_ERR;

    uint64_t *P1 = pk;
    uint64_t *P2 = P1 + PARAM_P1_limbs(p);
    uint64_t *P3 = P2 + PARAM_P2_limbs(p);
#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < PARAM_P1_limbs(p); ++i)
        P1[i] = BSWAP64(P1[i]);
    for (int i = 0; i < PARAM_P2_limbs(p); ++i)
        P2[i] = BSWAP64(P2[i]);
    for (int i = 0; i < PARAM_P3_limbs(p); ++i)
        P3[i] = BSWAP64(P3[i]);
#endif

    if (nibs_target_enc(p, tEnc, m, mlen, sig + s_bytes, (size_t)param_salt_bytes) != MAYO_OK)
        return MAYO_ERR;
    decode(tEnc, t, param_m);
    decode(sig, s, param_k * param_n);
    eval_public_map(p, s, P1, P2, P3, y);
    return memcmp(y, t, param_m) == 0 ? MAYO_OK : MAYO_ERR;
}
