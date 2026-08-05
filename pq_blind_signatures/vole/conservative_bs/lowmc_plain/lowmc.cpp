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

constexpr unsigned BLOCKSIZE = NIBS_LOWMC_BLOCK_BITS;
constexpr unsigned BLOCKBYTES = NIBS_LOWMC_BLOCK_BYTES;
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

// Reference rank computation, generalised only in that `size` is a 
// parameter instead of the bitset width.
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

    std::vector<std::vector<block>>    LinMatrices;   // [rounds][n] rows
    std::vector<block>                 roundconstants;// [rounds]
    std::vector<std::vector<keyblock>> KeyMatrices;   // [rounds+1][n] rows

    // Flattened, bit-packed exports (row-major, n/8 B/row) for the circuit.
    std::vector<uint8_t> lin_flat;   // rounds * n * n/8
    std::vector<uint8_t> key_flat;   // (rounds+1) * n * n/8
    std::vector<uint8_t> rc_flat;    // rounds * n/8

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
            std::memset(out, 0, BLOCKBYTES);
            for (unsigned i = 0; i < BLOCKSIZE; ++i)
                if (b[i]) out[i >> 3] |= uint8_t(1u << (i & 7));
        };
        lin_flat.assign(size_t(rounds) * BLOCKSIZE * BLOCKBYTES, 0);
        for (unsigned r = 0; r < rounds; ++r)
            for (unsigned i = 0; i < BLOCKSIZE; ++i)
                pack(LinMatrices[r][i],
                     &lin_flat[(size_t(r) * BLOCKSIZE + i) * BLOCKBYTES]);
        key_flat.assign(size_t(rounds + 1) * BLOCKSIZE * BLOCKBYTES, 0);
        for (unsigned r = 0; r <= rounds; ++r)
            for (unsigned i = 0; i < BLOCKSIZE; ++i)
                pack(KeyMatrices[r][i],
                     &key_flat[(size_t(r) * BLOCKSIZE + i) * BLOCKBYTES]);
        rc_flat.assign(size_t(rounds) * BLOCKBYTES, 0);
        for (unsigned r = 0; r < rounds; ++r)
            pack(roundconstants[r], &rc_flat[size_t(r) * BLOCKBYTES]);
    }
};

const unsigned LowMCInst::Sbox[8] = {0x00, 0x01, 0x03, 0x06,
                                     0x07, 0x04, 0x05, 0x02};

LowMCInst* g_inst = nullptr;

block load_block(const uint8_t* bytes)
{
    block b = 0;
    for (unsigned i = 0; i < BLOCKSIZE; ++i)
        if ((bytes[i >> 3] >> (i & 7)) & 1) b[i] = 1;
    return b;
}

void store_block(const block& b, uint8_t* bytes)
{
    std::memset(bytes, 0, BLOCKBYTES);
    for (unsigned i = 0; i < BLOCKSIZE; ++i)
        if (b[i]) bytes[i >> 3] |= uint8_t(1u << (i & 7));
}

} // namespace

extern "C" {

void nibs_lowmc_init(void)
{
    if (g_inst) return;
    g_inst = new LowMCInst(NIBS_LOWMC_BOXES, NIBS_LOWMC_KEY_BITS,
                           NIBS_LOWMC_ROUNDS);
}

unsigned nibs_lowmc_param_level(void) { return NIBS_LOWMC_LEVEL; }

void nibs_lowmc_encrypt(const uint8_t* key, const uint8_t* pt, uint8_t* ct)
{
    block c = g_inst->encrypt(load_block(key), load_block(pt));
    store_block(c, ct);
}

void nibs_lowmc_witness_states(const uint8_t* key, const uint8_t* pt,
                               uint8_t* states, uint8_t* ct)
{
    std::vector<block> post;
    block c = g_inst->encrypt(load_block(key), load_block(pt), &post);
    for (unsigned r = 0; r < NIBS_LOWMC_ROUNDS; ++r)
        store_block(post[r], states + size_t(r) * BLOCKBYTES);
    if (ct) store_block(c, ct);
}

const uint8_t* nibs_lowmc_linmat(unsigned r)
{
    return &g_inst->lin_flat[size_t(r) * BLOCKSIZE * BLOCKBYTES];
}
const uint8_t* nibs_lowmc_keymat(unsigned r)
{
    return &g_inst->key_flat[size_t(r) * BLOCKSIZE * BLOCKBYTES];
}
const uint8_t* nibs_lowmc_roundconst(unsigned r)
{
    return &g_inst->rc_flat[size_t(r) * BLOCKBYTES];
}

void nibs_derive_message(const uint8_t* K, const uint8_t* r, uint8_t* m)
{
    nibs_lowmc_encrypt(K, r, m);
}

void nibs_lowmc_witness_expand(const uint8_t* K, const uint8_t* r,
                               uint8_t* out, uint8_t* m_out)
{
    static_assert(NIBS_LOWMC_KEY_BYTES + NIBS_LOWMC_NONCE_BYTES +
                      NIBS_LOWMC_STATE_BYTES ==
                  NIBS_LOWMC_WITNESS_BYTES, "witness layout mismatch");

    uint8_t* p = out;
    std::memcpy(p, K, NIBS_LOWMC_KEY_BYTES);   p += NIBS_LOWMC_KEY_BYTES;
    std::memcpy(p, r, NIBS_LOWMC_NONCE_BYTES); p += NIBS_LOWMC_NONCE_BYTES;

    nibs_lowmc_witness_states(K, r, p, m_out);
}

} // extern "C"
