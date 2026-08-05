// Portions of this file are derived from the LowMC reference implementation:
// https://github.com/LowMC/lowmc
//
// Original work licensed under the MIT License.
// Modifications for this project are Copyright (c) 2026 Thomas Chandler.

#include "lowmc.hpp"

#include <bitset>
#include <vector>
#include <cassert>
#include <cstring>
#include <algorithm>

namespace {

constexpr unsigned BLOCKSIZE = 256;
using block    = std::bitset<BLOCKSIZE>;
using keyblock = std::bitset<BLOCKSIZE>; // low `keysize` bits used

// --- PRG: self-shrinking 80-bit LFSR, process-global (reference-faithful) ---
std::bitset<80> g_lfsr;      // zero-initialised => "not initialised yet"

bool getrandbit()
{
    bool tmp = 0;
    if (g_lfsr.none()) {
        g_lfsr.set();
        for (unsigned i = 0; i < 160; ++i) {
            tmp = g_lfsr[0] ^ g_lfsr[13] ^ g_lfsr[23] ^ g_lfsr[38] ^
                  g_lfsr[51] ^ g_lfsr[62];
            g_lfsr >>= 1;
            g_lfsr[79] = tmp;
        }
    }
    bool choice = false;
    do {
        tmp = g_lfsr[0] ^ g_lfsr[13] ^ g_lfsr[23] ^ g_lfsr[38] ^
              g_lfsr[51] ^ g_lfsr[62];
        g_lfsr >>= 1;
        g_lfsr[79] = tmp;
        choice = tmp;
        tmp = g_lfsr[0] ^ g_lfsr[13] ^ g_lfsr[23] ^ g_lfsr[38] ^
              g_lfsr[51] ^ g_lfsr[62];
        g_lfsr >>= 1;
        g_lfsr[79] = tmp;
    } while (!choice);
    return tmp;
}

// Reference rank computation, generalised only in that `size` (the number
// of columns scanned, from bit size-1 downwards) is a parameter instead of
// the bitset width. With size == width this is the reference verbatim.
template <typename BS>
unsigned rank_of_matrix(const std::vector<BS>& matrix, unsigned size)
{
    std::vector<BS> mat(matrix);
    unsigned row = 0;
    for (unsigned col = 1; col <= size; ++col) {
        if (!mat[row][size - col]) {
            unsigned r = row;
            while (r < mat.size() && !mat[r][size - col]) ++r;
            if (r >= mat.size()) continue;
            std::swap(mat[row], mat[r]);
        }
        for (unsigned i = row + 1; i < mat.size(); ++i)
            if (mat[i][size - col]) mat[i] ^= mat[row];
        ++row;
        if (row == size) break;
    }
    return row;
}

struct LowMCInst {
    unsigned numofboxes;
    unsigned keysize;
    unsigned rounds;
    unsigned identitysize; // blocksize - 3*numofboxes

    std::vector<std::vector<block>>    LinMatrices;   // [rounds][256] rows
    std::vector<block>                 roundconstants;// [rounds]
    std::vector<std::vector<keyblock>> KeyMatrices;   // [rounds+1][256] rows

    // Flattened, bit-packed exports (row-major, 32 B/row) for the circuit.
    std::vector<uint8_t> lin_flat;   // rounds * 256 * 32
    std::vector<uint8_t> key_flat;   // (rounds+1) * 256 * 32
    std::vector<uint8_t> rc_flat;    // rounds * 32

    static const unsigned Sbox[8];

    LowMCInst(unsigned boxes, unsigned ksize, unsigned nrounds)
        : numofboxes(boxes), keysize(ksize), rounds(nrounds),
          identitysize(BLOCKSIZE - 3 * boxes)
    {
        instantiate();
        flatten();
    }

    block getrandblock() const
    {
        block tmp = 0;
        for (unsigned i = 0; i < BLOCKSIZE; ++i) tmp[i] = getrandbit();
        return tmp;
    }
    keyblock getrandkeyblock() const
    {
        keyblock tmp = 0;
        for (unsigned i = 0; i < keysize; ++i) tmp[i] = getrandbit();
        return tmp;
    }

    void instantiate()
    {
        // Reference instantiate_LowMC(), minus inverse matrices (which
        // consume no PRG bits, so constants are unaffected).
        LinMatrices.clear();
        for (unsigned r = 0; r < rounds; ++r) {
            std::vector<block> mat;
            do {
                mat.clear();
                for (unsigned i = 0; i < BLOCKSIZE; ++i)
                    mat.push_back(getrandblock());
            } while (rank_of_matrix(mat, BLOCKSIZE) != BLOCKSIZE);
            LinMatrices.push_back(mat);
        }
        roundconstants.clear();
        for (unsigned r = 0; r < rounds; ++r)
            roundconstants.push_back(getrandblock());
        KeyMatrices.clear();
        for (unsigned r = 0; r <= rounds; ++r) {
            std::vector<keyblock> mat;
            do {
                mat.clear();
                for (unsigned i = 0; i < BLOCKSIZE; ++i)
                    mat.push_back(getrandkeyblock());
            } while (rank_of_matrix(mat, keysize) <
                     std::min(BLOCKSIZE, keysize));
            KeyMatrices.push_back(mat);
        }
    }

    static block mul_matrix(const std::vector<block>& matrix, const block& msg)
    {
        block temp = 0;
        for (unsigned i = 0; i < BLOCKSIZE; ++i)
            temp[i] = (msg & matrix[i]).count() % 2;
        return temp;
    }

    block substitution(const block& message) const
    {
        block temp = 0;
        temp ^= (message >> 3 * numofboxes); // identity part (top bits)
        for (unsigned i = 1; i <= numofboxes; ++i) {
            temp <<= 3;
            temp ^= block(Sbox[((message >> 3 * (numofboxes - i)) &
                                block(0x7)).to_ulong()]);
        }
        return temp;
    }

    std::vector<block> roundkeys_for(const keyblock& key) const
    {
        std::vector<block> rk;
        for (unsigned r = 0; r <= rounds; ++r)
            rk.push_back(mul_matrix(KeyMatrices[r], key));
        return rk;
    }

    // encrypt, optionally recording every post-S-box state.
    block encrypt(const keyblock& key, const block& message,
                  std::vector<block>* post_sbox = nullptr) const
    {
        auto rk = roundkeys_for(key);
        block c = message ^ rk[0];
        for (unsigned r = 1; r <= rounds; ++r) {
            c = substitution(c);
            if (post_sbox) post_sbox->push_back(c);
            c = mul_matrix(LinMatrices[r - 1], c);
            c ^= roundconstants[r - 1];
            c ^= rk[r];
        }
        return c;
    }

    void flatten()
    {
        auto pack = [](const block& b, uint8_t* out) {
            std::memset(out, 0, 32);
            for (unsigned i = 0; i < BLOCKSIZE; ++i)
                if (b[i]) out[i >> 3] |= uint8_t(1u << (i & 7));
        };
        lin_flat.assign(size_t(rounds) * 256 * 32, 0);
        for (unsigned r = 0; r < rounds; ++r)
            for (unsigned i = 0; i < 256; ++i)
                pack(LinMatrices[r][i], &lin_flat[(size_t(r) * 256 + i) * 32]);
        key_flat.assign(size_t(rounds + 1) * 256 * 32, 0);
        for (unsigned r = 0; r <= rounds; ++r)
            for (unsigned i = 0; i < 256; ++i)
                pack(KeyMatrices[r][i], &key_flat[(size_t(r) * 256 + i) * 32]);
        rc_flat.assign(size_t(rounds) * 32, 0);
        for (unsigned r = 0; r < rounds; ++r)
            pack(roundconstants[r], &rc_flat[size_t(r) * 32]);
    }
};

const unsigned LowMCInst::Sbox[8] = {0x00, 0x01, 0x03, 0x06,
                                     0x07, 0x04, 0x05, 0x02};

LowMCInst* g_inst[2] = {nullptr, nullptr};

block load_block(const uint8_t* bytes)
{
    block b = 0;
    for (unsigned i = 0; i < BLOCKSIZE; ++i)
        if ((bytes[i >> 3] >> (i & 7)) & 1) b[i] = 1;
    return b;
}

void store_block(const block& b, uint8_t* bytes)
{
    std::memset(bytes, 0, 32);
    for (unsigned i = 0; i < BLOCKSIZE; ++i)
        if (b[i]) bytes[i >> 3] |= uint8_t(1u << (i & 7));
}

} // namespace

extern "C" {

void nibs_lowmc_init(void)
{
    if (g_inst[0]) return;
    // ORDER IS PART OF THE SPEC (shared PRG stream): HASH first, PRF second.
    g_inst[NIBS_LOWMC_HASH] =
        new LowMCInst(NIBS_LOWMC_BOXES, 256, NIBS_LOWMC_HASH_ROUNDS);
    g_inst[NIBS_LOWMC_PRF] =
        new LowMCInst(NIBS_LOWMC_BOXES, 256, NIBS_LOWMC_PRF_ROUNDS);
}

unsigned nibs_lowmc_rounds(int inst) { return g_inst[inst]->rounds; }

void nibs_lowmc_encrypt(int inst, const uint8_t* key, const uint8_t* pt,
                        uint8_t* ct)
{
    block c = g_inst[inst]->encrypt(load_block(key), load_block(pt));
    store_block(c, ct);
}

void nibs_lowmc_mmo(const uint8_t* chain, const uint8_t* msg, uint8_t* out)
{
    uint8_t ct[32];
    nibs_lowmc_encrypt(NIBS_LOWMC_HASH, chain, msg, ct);
    for (unsigned i = 0; i < 32; ++i) out[i] = ct[i] ^ msg[i];
}

void nibs_lowmc_witness_states(int inst, const uint8_t* key,
                               const uint8_t* pt, uint8_t* states,
                               uint8_t* ct)
{
    std::vector<block> post;
    block c = g_inst[inst]->encrypt(load_block(key), load_block(pt), &post);
    for (unsigned r = 0; r < g_inst[inst]->rounds; ++r)
        store_block(post[r], states + size_t(r) * 32);
    if (ct) store_block(c, ct);
}

const uint8_t* nibs_lowmc_linmat(int inst, unsigned r)
{
    return &g_inst[inst]->lin_flat[size_t(r) * 256 * 32];
}
const uint8_t* nibs_lowmc_keymat(int inst, unsigned r)
{
    return &g_inst[inst]->key_flat[size_t(r) * 256 * 32];
}
const uint8_t* nibs_lowmc_roundconst(int inst, unsigned r)
{
    return &g_inst[inst]->rc_flat[size_t(r) * 32];
}

void nibs_lowmc_build_pt(uint8_t dom, const uint8_t* payload16, uint8_t* pt)
{
    std::memset(pt, 0, NIBS_LOWMC_BLOCK_BYTES);
    pt[0] = dom;
    if (payload16) std::memcpy(pt + 1, payload16, 16);
}

void nibs_derive_pkr(const uint8_t* skR, const uint8_t* open, uint8_t* pkR)
{
    uint8_t pt[32];
    nibs_lowmc_build_pt(NIBS_DOM_PK, open, pt);
    nibs_lowmc_encrypt(NIBS_LOWMC_PRF, skR, pt, pkR);
}

void nibs_derive_com(const uint8_t* pkR, const uint8_t* nonce, uint8_t* com)
{
    uint8_t pt[32];
    nibs_lowmc_build_pt(NIBS_DOM_COM, nonce, pt);
    nibs_lowmc_mmo(pkR, pt, com);
}

void nibs_derive_message(const uint8_t* skR, const uint8_t* nonce, uint8_t* m)
{
    uint8_t pt[32];
    nibs_lowmc_build_pt(NIBS_DOM_M, nonce, pt);
    nibs_lowmc_encrypt(NIBS_LOWMC_PRF, skR, pt, m);
}

// Fills the LowMC region only (1600 B): skR | open | nonce | GadA states |
// Gad1 states | GadM states. The Rain gadget-2 region and the MAYO preimage
// are appended by the caller (get_witness_nibs / MAYO packing). com_out
// receives com = MMO(pkR, PT(DOM_COM, nonce)) so the caller can build the
// Rain in-block (com | salt | cap).
void nibs_lowmc_witness_expand(const uint8_t* skR, const uint8_t* open,
                               const uint8_t* nonce, uint8_t* out,
                               uint8_t* com_out)
{
    uint8_t* p = out;
    std::memcpy(p, skR, 32);   p += 32;
    std::memcpy(p, open, 16);  p += 16;
    std::memcpy(p, nonce, 16); p += 16;

    uint8_t pt[32], pkR[32], e1[32];

    // GadA: pkR = E^PRF_skR(PT(DOM_PK, open))
    nibs_lowmc_build_pt(NIBS_DOM_PK, open, pt);
    nibs_lowmc_witness_states(NIBS_LOWMC_PRF, skR, pt, p, pkR);
    p += NIBS_LOWMC_PRF_ROUNDS * 32;

    // Gad1: com = E^HASH_pkR(PT(DOM_COM, nonce)) ^ PT (MMO)
    nibs_lowmc_build_pt(NIBS_DOM_COM, nonce, pt);
    nibs_lowmc_witness_states(NIBS_LOWMC_HASH, pkR, pt, p, e1);
    for (unsigned i = 0; i < 32; ++i) com_out[i] = e1[i] ^ pt[i];
    p += NIBS_LOWMC_HASH_ROUNDS * 32;

    // GadM: m = E^PRF_skR(PT(DOM_M, nonce))
    nibs_lowmc_build_pt(NIBS_DOM_M, nonce, pt);
    nibs_lowmc_witness_states(NIBS_LOWMC_PRF, skR, pt, p, nullptr);
}

} // extern "C"

// ---------------------------------------------------------------------------
// Port-fidelity KAT hook (test builds only): fresh instance at the reference
// repo's default parameters (keysize=80, boxes=49, rounds=12) on the current
// PRG stream. Call ONLY from a fresh process, before nibs_lowmc_init(), so
// the stream state matches a fresh run of the pristine reference.
// ---------------------------------------------------------------------------
#ifdef LOWMC_PORT_TEST
extern "C" void nibs_lowmc_port_kat(const uint8_t key10[10],
                                    const uint8_t pt32[32], uint8_t ct32[32])
{
    static LowMCInst* ref = nullptr;
    if (!ref) ref = new LowMCInst(49, 80, 12);
    keyblock k = 0;
    for (unsigned i = 0; i < 80; ++i)
        if ((key10[i >> 3] >> (i & 7)) & 1) k[i] = 1;
    store_block(ref->encrypt(k, load_block(pt32)), ct32);
}
#endif
