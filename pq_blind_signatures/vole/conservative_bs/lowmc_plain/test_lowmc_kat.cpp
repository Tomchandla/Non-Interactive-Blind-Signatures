// test_lowmc_kat.cpp
//
// Two test layers:
//

#include "lowmc.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <bitset>
#include <vector>

static void hexprint(const char* label, const uint8_t* b, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", b[i]);
    printf("\n");
}

static const unsigned SBOX[8] = {0, 1, 3, 6, 7, 4, 5, 2};

static void matvec(const uint8_t* rows /*256x32*/, const uint8_t in[32],
                   uint8_t out[32])
{
    memset(out, 0, 32);
    for (unsigned i = 0; i < 256; ++i) {
        const uint8_t* row = rows + i * 32;
        unsigned acc = 0;
        for (unsigned j = 0; j < 32; ++j)
            acc ^= (unsigned)(row[j] & in[j]);
        acc ^= acc >> 4; acc ^= acc >> 2; acc ^= acc >> 1;
        out[i >> 3] |= (uint8_t)((acc & 1u) << (i & 7));
    }
}

static int getbit(const uint8_t* b, unsigned i) { return (b[i >> 3] >> (i & 7)) & 1; }
static void setbit(uint8_t* b, unsigned i, int v)
{
    if (v) b[i >> 3] |= (uint8_t)(1u << (i & 7));
    else   b[i >> 3] &= (uint8_t)~(1u << (i & 7));
}

static void sbox_layer(const uint8_t in[32], uint8_t out[32])
{
    memcpy(out, in, 32); // identity bit 255 carried through
    for (unsigned bx = 0; bx < NIBS_LOWMC_BOXES; ++bx) {
        int c = getbit(in, 3 * bx + 0);
        int b = getbit(in, 3 * bx + 1);
        int a = getbit(in, 3 * bx + 2);
        unsigned v = (unsigned)((a << 2) | (b << 1) | c);
        unsigned s = SBOX[v];
        setbit(out, 3 * bx + 0, (int)(s & 1));
        setbit(out, 3 * bx + 1, (int)((s >> 1) & 1));
        setbit(out, 3 * bx + 2, (int)((s >> 2) & 1));
    }
}

static int check_witness_consistency(int inst, const uint8_t key[32],
                                     const uint8_t pt[32])
{
    unsigned R = nibs_lowmc_rounds(inst);
    std::vector<uint8_t> states(R * 32);
    uint8_t ct[32], rk[32], acc[32], sb[32];
    nibs_lowmc_witness_states(inst, key, pt, states.data(), ct);

    //in_1 = pt ^ K0 key-schedule row product
    matvec(nibs_lowmc_keymat(inst, 0), key, rk);
    for (unsigned j = 0; j < 32; ++j) acc[j] = pt[j] ^ rk[j];

    for (unsigned r = 1; r <= R; ++r) {
        sbox_layer(acc, sb);
        if (memcmp(sb, &states[(r - 1) * 32], 32) != 0) {
            printf("  FAIL: inst %d round %u post-Sbox mismatch\n", inst, r);
            return 1;
        }
        uint8_t lin[32];
        matvec(nibs_lowmc_linmat(inst, r - 1), sb, lin);
        matvec(nibs_lowmc_keymat(inst, r), key, rk);
        const uint8_t* rc = nibs_lowmc_roundconst(inst, r - 1);
        for (unsigned j = 0; j < 32; ++j) acc[j] = lin[j] ^ rc[j] ^ rk[j];
    }
    if (memcmp(acc, ct, 32) != 0) {
        printf("  FAIL: inst %d ciphertext mismatch\n", inst);
        return 1;
    }
    return 0;
}

int main()
{
    nibs_lowmc_init();
    int fails = 0;

    printf("[1] NIBS derivation chain self-consistency\n");
    {
        uint8_t skR[32], open[16], nonce[16];
        for (int i = 0; i < 32; ++i) skR[i] = (uint8_t)(0xA0 + i);
        for (int i = 0; i < 16; ++i) { open[i] = (uint8_t)(0x50 + i); nonce[i] = (uint8_t)i; }
        uint8_t pkR[32], m[32];
        nibs_derive_pkr(skR, open, pkR);
        nibs_derive_message(skR, nonce, m);
        hexprint("  pkR = ", pkR, 32);
        hexprint("  m   = ", m, 32);

        // witness expansion agrees with the derivations
        uint8_t wit[NIBS_LOWMC_WITNESS_BYTES], pkr2[32];
        nibs_lowmc_witness_expand(skR, open, nonce, wit, pkr2);
        if (memcmp(wit, skR, 32) || memcmp(wit + 32, open, 16) ||
            memcmp(wit + 48, nonce, 16)) {
            printf("  FAIL: witness header mismatch\n"); ++fails;
        } else if (memcmp(pkR, pkr2, 32)) {
            printf("  FAIL: witness-expansion pkR != derive_pkr\n"); ++fails;
        } else printf("  witness header + pkR ok (%d bytes total)\n",
                      (int)NIBS_LOWMC_WITNESS_BYTES);
    }

    printf("[2] domain separation m != pkR over 10000 random (skR, open, nonce)\n");
    {
        int bad = 0;
        for (int trial = 0; trial < 10000; ++trial) {
            uint8_t skR[32], open[16], nonce[16], pkR[32], m[32];
            for (int i = 0; i < 32; ++i) skR[i] = (uint8_t)rand();
            for (int i = 0; i < 16; ++i) { open[i] = (uint8_t)rand(); nonce[i] = (uint8_t)rand(); }
            nibs_derive_pkr(skR, open, pkR);
            nibs_derive_message(skR, nonce, m);
            if (!memcmp(pkR, m, 32)) ++bad;
        }
        if (bad) { printf("  FAIL: %d collisions\n", bad); ++fails; }
        else printf("  ok\n");
    }

    printf(fails ? "\nRESULT: FAILED\n" : "\nRESULT: all self-tests passed\n");
    return fails ? 1 : 0;
}
