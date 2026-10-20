// Portions of this file are derived from the LowMC reference implementation:
// https://github.com/LowMC/lowmc
//
// Original work licensed under the MIT License.
//
// Changes for NIBS:
//  * one instance per NIST level (1, 3, 5), each generated from a fresh
//    LFSR so that every instance is bit-for-bit the instance the reference
//    implementation produces for the same (n, m, k, r);
//  * encryption can record the post-S-box state of every round (the VOLEitH
//    witness);
//  * the public matrices are exported in a flattened row-major form for the
//    circuit;
//  * decryption (inverse S-box, inverse linear layers) is kept, so that the
//    keyed permutation and its inverse are both available, as required for a
//    strong PRP.

#include "lowmc.hpp"

#include <algorithm>
#include <bitset>
#include <cassert>
#include <cstring>
#include <mutex>
#include <vector>

namespace nibs_lowmc
{
namespace
{

template <unsigned LEVEL> class Inst
{
public:
    using D = derived<LEVEL>;
    static constexpr unsigned N = D::BLOCK_BITS;
    static constexpr unsigned K = D::KEY_BITS;
    static constexpr unsigned BOXES = D::BOXES;
    static constexpr unsigned ROUNDS = D::ROUNDS;
    static constexpr unsigned BYTES = D::BLOCK_BYTES;
    using block = std::bitset<N>;

    std::vector<std::vector<block>> lin, inv_lin, keymats; // keymats: rows of K used bits
    std::vector<block> rcs;
    std::vector<uint8_t> lin_flat, key_flat, rc_flat;

    Inst()
    {
        lfsr_.reset();
        instantiate();
        flatten();
    }

    // ---- primitive ------------------------------------------------------
    block encrypt(const block& key, const block& pt, std::vector<block>* post = nullptr) const
    {
        block c = pt ^ mul(keymats[0], key);
        for (unsigned r = 1; r <= ROUNDS; ++r)
        {
            c = sub(c, SBOX);
            if (post)
                post->push_back(c);
            c = mul(lin[r - 1], c);
            c ^= rcs[r - 1];
            c ^= mul(keymats[r], key);
        }
        return c;
    }

    block decrypt(const block& key, const block& ct) const
    {
        block c = ct;
        for (unsigned r = ROUNDS; r > 0; --r)
        {
            c ^= mul(keymats[r], key);
            c ^= rcs[r - 1];
            c = mul(inv_lin[r - 1], c);
            c = sub(c, INV_SBOX);
        }
        return c ^ mul(keymats[0], key);
    }

    static block load(const uint8_t* bytes)
    {
        block b;
        for (unsigned i = 0; i < N; ++i)
            b[i] = (bytes[i >> 3] >> (i & 7)) & 1;
        return b;
    }
    static void store(const block& b, uint8_t* bytes)
    {
        std::memset(bytes, 0, BYTES);
        for (unsigned i = 0; i < N; ++i)
            if (b[i])
                bytes[i >> 3] |= uint8_t(1u << (i & 7));
    }

private:
    static constexpr unsigned SBOX[8] = {0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02};
    static constexpr unsigned INV_SBOX[8] = {0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04};

    std::bitset<80> lfsr_;

    // Self-shrinking 80-bit LFSR, exactly as in the reference implementation.
    bool randbit()
    {
        bool tmp = 0;
        if (lfsr_.none())
        {
            lfsr_.set();
            for (unsigned i = 0; i < 160; ++i)
            {
                tmp = lfsr_[0] ^ lfsr_[13] ^ lfsr_[23] ^ lfsr_[38] ^ lfsr_[51] ^ lfsr_[62];
                lfsr_ >>= 1;
                lfsr_[79] = tmp;
            }
        }
        bool choice = false;
        do
        {
            tmp = lfsr_[0] ^ lfsr_[13] ^ lfsr_[23] ^ lfsr_[38] ^ lfsr_[51] ^ lfsr_[62];
            lfsr_ >>= 1;
            lfsr_[79] = tmp;
            choice = tmp;
            tmp = lfsr_[0] ^ lfsr_[13] ^ lfsr_[23] ^ lfsr_[38] ^ lfsr_[51] ^ lfsr_[62];
            lfsr_ >>= 1;
            lfsr_[79] = tmp;
        } while (!choice);
        return tmp;
    }

    block randblock(unsigned bits)
    {
        block b = 0;
        for (unsigned i = 0; i < bits; ++i)
            b[i] = randbit();
        return b;
    }

    // Rank over the first `size` columns, as in the reference.
    static unsigned rank(std::vector<block> mat, unsigned size)
    {
        unsigned row = 0;
        for (unsigned col = 1; col <= size; ++col)
        {
            if (!mat[row][size - col])
            {
                unsigned r = row;
                while (r < mat.size() && !mat[r][size - col])
                    ++r;
                if (r >= mat.size())
                    continue;
                std::swap(mat[row], mat[r]);
            }
            for (unsigned i = row + 1; i < mat.size(); ++i)
                if (mat[i][size - col])
                    mat[i] ^= mat[row];
            ++row;
            if (row == size)
                break;
        }
        return row;
    }

    static std::vector<block> invert(std::vector<block> mat)
    {
        std::vector<block> inv(N, 0);
        for (unsigned i = 0; i < N; ++i)
            inv[i][i] = 1;
        unsigned row = 0;
        for (unsigned col = 0; col < N; ++col)
        {
            if (!mat[row][col])
            {
                unsigned r = row + 1;
                while (r < mat.size() && !mat[r][col])
                    ++r;
                if (r >= mat.size())
                    continue;
                std::swap(mat[row], mat[r]);
                std::swap(inv[row], inv[r]);
            }
            for (unsigned i = row + 1; i < mat.size(); ++i)
                if (mat[i][col])
                {
                    mat[i] ^= mat[row];
                    inv[i] ^= inv[row];
                }
            ++row;
        }
        for (unsigned col = N; col > 0; --col)
            for (unsigned r = 0; r < col - 1; ++r)
                if (mat[r][col - 1])
                {
                    mat[r] ^= mat[col - 1];
                    inv[r] ^= inv[col - 1];
                }
        return inv;
    }

    void instantiate()
    {
        for (unsigned r = 0; r < ROUNDS; ++r)
        {
            std::vector<block> m;
            do
            {
                m.clear();
                for (unsigned i = 0; i < N; ++i)
                    m.push_back(randblock(N));
            } while (rank(m, N) != N);
            lin.push_back(m);
            inv_lin.push_back(invert(m));
        }
        for (unsigned r = 0; r < ROUNDS; ++r)
            rcs.push_back(randblock(N));
        for (unsigned r = 0; r <= ROUNDS; ++r)
        {
            std::vector<block> m;
            do
            {
                m.clear();
                for (unsigned i = 0; i < N; ++i)
                    m.push_back(randblock(K));
            } while (rank(m, K) < std::min(N, K));
            keymats.push_back(m);
        }
    }

    static block mul(const std::vector<block>& m, const block& v)
    {
        block out = 0;
        for (unsigned i = 0; i < N; ++i)
            out[i] = (m[i] & v).count() & 1;
        return out;
    }

    static block sub(const block& x, const unsigned* box)
    {
        block t = 0;
        t ^= (x >> 3 * BOXES); // identity part
        for (unsigned i = 1; i <= BOXES; ++i)
        {
            t <<= 3;
            t ^= block(box[((x >> 3 * (BOXES - i)) & block(0x7)).to_ulong()]);
        }
        return t;
    }

    void flatten()
    {
        lin_flat.assign(size_t(ROUNDS) * N * BYTES, 0);
        for (unsigned r = 0; r < ROUNDS; ++r)
            for (unsigned i = 0; i < N; ++i)
                store(lin[r][i], &lin_flat[(size_t(r) * N + i) * BYTES]);
        key_flat.assign(size_t(ROUNDS + 1) * N * BYTES, 0);
        for (unsigned r = 0; r <= ROUNDS; ++r)
            for (unsigned i = 0; i < N; ++i)
                store(keymats[r][i], &key_flat[(size_t(r) * N + i) * BYTES]);
        rc_flat.assign(size_t(ROUNDS) * BYTES, 0);
        for (unsigned r = 0; r < ROUNDS; ++r)
            store(rcs[r], &rc_flat[size_t(r) * BYTES]);
    }
};

Inst<1>* g1 = nullptr;
Inst<3>* g3 = nullptr;
Inst<5>* g5 = nullptr;

template <unsigned LEVEL> const Inst<LEVEL>& inst()
{
    nibs_lowmc_init();
    if constexpr (LEVEL == 1)
        return *g1;
    else if constexpr (LEVEL == 3)
        return *g3;
    else
        return *g5;
}

template <unsigned LEVEL>
void encrypt_t(const uint8_t* key, const uint8_t* pt, uint8_t* ct, uint8_t* states)
{
    using I = Inst<LEVEL>;
    std::vector<typename I::block> post;
    auto c = inst<LEVEL>().encrypt(I::load(key), I::load(pt), states ? &post : nullptr);
    if (states)
        for (unsigned r = 0; r < I::ROUNDS; ++r)
            I::store(post[r], states + size_t(r) * I::BYTES);
    if (ct)
        I::store(c, ct);
}

template <unsigned LEVEL> void decrypt_t(const uint8_t* key, const uint8_t* ct, uint8_t* pt)
{
    using I = Inst<LEVEL>;
    I::store(inst<LEVEL>().decrypt(I::load(key), I::load(ct)), pt);
}

} // namespace

template <unsigned LEVEL> const uint8_t* linmat(unsigned r)
{
    assert(r < Inst<LEVEL>::ROUNDS);
    return &inst<LEVEL>().lin_flat[size_t(r) * Inst<LEVEL>::N * Inst<LEVEL>::BYTES];
}
template <unsigned LEVEL> const uint8_t* keymat(unsigned r)
{
    assert(r <= Inst<LEVEL>::ROUNDS);
    return &inst<LEVEL>().key_flat[size_t(r) * Inst<LEVEL>::N * Inst<LEVEL>::BYTES];
}
template <unsigned LEVEL> const uint8_t* roundconst(unsigned r)
{
    assert(r < Inst<LEVEL>::ROUNDS);
    return &inst<LEVEL>().rc_flat[size_t(r) * Inst<LEVEL>::BYTES];
}

template const uint8_t* linmat<1>(unsigned);
template const uint8_t* linmat<3>(unsigned);
template const uint8_t* linmat<5>(unsigned);
template const uint8_t* keymat<1>(unsigned);
template const uint8_t* keymat<3>(unsigned);
template const uint8_t* keymat<5>(unsigned);
template const uint8_t* roundconst<1>(unsigned);
template const uint8_t* roundconst<3>(unsigned);
template const uint8_t* roundconst<5>(unsigned);

} // namespace nibs_lowmc

using namespace nibs_lowmc;

extern "C" {

void nibs_lowmc_init(void)
{
    static std::once_flag once;
    std::call_once(once,
                   []
                   {
                       g1 = new Inst<1>();
                       g3 = new Inst<3>();
                       g5 = new Inst<5>();
                   });
}

unsigned nibs_lowmc_block_bytes(unsigned level)
{
    return level == 1 ? derived<1>::BLOCK_BYTES
         : level == 3 ? derived<3>::BLOCK_BYTES
                      : derived<5>::BLOCK_BYTES;
}

unsigned nibs_lowmc_rounds(unsigned level)
{
    return level == 1 ? derived<1>::ROUNDS : level == 3 ? derived<3>::ROUNDS : derived<5>::ROUNDS;
}

void nibs_lowmc_encrypt(unsigned level, const uint8_t* key, const uint8_t* pt, uint8_t* ct)
{
    nibs_lowmc_witness_states(level, key, pt, nullptr, ct);
}

void nibs_lowmc_decrypt(unsigned level, const uint8_t* key, const uint8_t* ct, uint8_t* pt)
{
    switch (level)
    {
    case 1: decrypt_t<1>(key, ct, pt); break;
    case 3: decrypt_t<3>(key, ct, pt); break;
    case 5: decrypt_t<5>(key, ct, pt); break;
    default: assert(false && "LowMC level must be 1, 3 or 5");
    }
}

void nibs_lowmc_witness_states(unsigned level, const uint8_t* key, const uint8_t* pt,
                               uint8_t* states, uint8_t* ct)
{
    switch (level)
    {
    case 1: encrypt_t<1>(key, pt, ct, states); break;
    case 3: encrypt_t<3>(key, pt, ct, states); break;
    case 5: encrypt_t<5>(key, pt, ct, states); break;
    default: assert(false && "LowMC level must be 1, 3 or 5");
    }
}

} // extern "C"
