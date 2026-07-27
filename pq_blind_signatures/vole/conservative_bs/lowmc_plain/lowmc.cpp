// lowmc.cpp -- see lowmc.hpp for the spec and the list of deviations from
// the reference implementation at https://github.com/LowMC/lowmc.

#include <vector>
#include <bitset>
#include <cassert>
#include <cstring>
#include <algorithm>

#include "lowmc.hpp"

namespace {

constexpr unsigned blocksize = 256;
using block    = std::bitset<blocksize>;
using keyblock = std::bitset<blocksize>;


//////////////////////////////
//     The LowMC class      //
//////////////////////////////

class LowMC {
public:
    LowMC (unsigned boxes, unsigned ksize, unsigned nrounds)
        : numofboxes(boxes), keysize(ksize), rounds(nrounds),
          identitysize(blocksize - 3*boxes) {
        instantiate_LowMC();
        flatten();
    }

    block encrypt (const keyblock key, const block message,
                   std::vector<block>* post_sbox = nullptr) const;

    unsigned numofboxes;
    unsigned keysize;
    unsigned rounds;
    unsigned identitysize;

    std::vector<std::vector<block>>    LinMatrices;    //[rounds][256] rows
    std::vector<block>                 roundconstants; //[rounds]
    std::vector<std::vector<keyblock>> KeyMatrices;    //[rounds+1][256] rows

    //Flattened, bit-packed exports (row-major, 32 B/row) for the circuit
    std::vector<uint8_t> lin_flat;  //rounds * 256 * 32
    std::vector<uint8_t> key_flat;  //(rounds+1) * 256 * 32
    std::vector<uint8_t> rc_flat;   //rounds * 32

private:
    block Substitution (const block message) const;

    block MultiplyWithGF2Matrix
        (const std::vector<block> matrix, const block message) const;
    block MultiplyWithGF2Matrix_Key
        (const std::vector<keyblock> matrix, const keyblock k) const;

    std::vector<block> keyschedule (const keyblock key) const;

    void instantiate_LowMC ();
    void flatten ();

    unsigned rank_of_Matrix (const std::vector<block> matrix) const;
    unsigned rank_of_Matrix_Key (const std::vector<keyblock> matrix) const;

    block    getrandblock () const;
    keyblock getrandkeyblock () const;

    static const unsigned Sbox[8];
};

const unsigned LowMC::Sbox[8] = {0x00, 0x01, 0x03, 0x06,
                                 0x07, 0x04, 0x05, 0x02};


/////////////////////////////
//     LowMC functions     //
/////////////////////////////

// Optionally records every post-S-box state
block LowMC::encrypt (const keyblock key, const block message,
                      std::vector<block>* post_sbox) const {
    auto roundkeys = keyschedule(key);
    block c = message ^ roundkeys[0];
    for (unsigned r = 1; r <= rounds; ++r) {
        c =  Substitution(c);
        if (post_sbox) post_sbox->push_back(c);
        c =  MultiplyWithGF2Matrix(LinMatrices[r-1], c);
        c ^= roundconstants[r-1];
        c ^= roundkeys[r];
    }
    return c;
}

// No need for decrypt in NIBS


/////////////////////////////
// LowMC private functions //
/////////////////////////////


block LowMC::Substitution (const block message) const {
    block temp = 0;
    //Get the identity part of the message
    temp ^= (message >> 3*numofboxes);
    //Get the rest through the Sboxes
    for (unsigned i = 1; i <= numofboxes; ++i) {
        temp <<= 3;
        temp ^= block(Sbox[ ((message >> 3*(numofboxes-i))
                            & block(0x7)).to_ulong() ]);
    }
    return temp;
}

// No need for invSubstitution here as decrypt is not used for NIBS


block LowMC::MultiplyWithGF2Matrix
        (const std::vector<block> matrix, const block message) const {
    block temp = 0;
    for (unsigned i = 0; i < blocksize; ++i) {
        temp[i] = (message & matrix[i]).count() % 2;
    }
    return temp;
}


block LowMC::MultiplyWithGF2Matrix_Key
        (const std::vector<keyblock> matrix, const keyblock k) const {
    block temp = 0;
    for (unsigned i = 0; i < blocksize; ++i) {
        temp[i] = (k & matrix[i]).count() % 2;
    }
    return temp;
}


// Deviation: returns the round keys instead of setting a member, so one
// instance can serve many keys concurrently.
std::vector<block> LowMC::keyschedule (const keyblock key) const {
    std::vector<block> roundkeys;
    for (unsigned r = 0; r <= rounds; ++r) {
        roundkeys.push_back( MultiplyWithGF2Matrix_Key (KeyMatrices[r], key) );
    }
    return roundkeys;
}


void LowMC::instantiate_LowMC () {
    // Create LinMatrices
    // Remove invLinMatrices as there is no decryption path.
    LinMatrices.clear();
    for (unsigned r = 0; r < rounds; ++r) {
        // Create matrix
        std::vector<block> mat;
        // Fill matrix with random bits
        do {
            mat.clear();
            for (unsigned i = 0; i < blocksize; ++i) {
                mat.push_back( getrandblock () );
            }
        // Repeat if matrix is not invertible
        } while ( rank_of_Matrix(mat) != blocksize );
        LinMatrices.push_back(mat);
    }

    // Create roundconstants
    roundconstants.clear();
    for (unsigned r = 0; r < rounds; ++r) {
        roundconstants.push_back( getrandblock () );
    }

    // Create KeyMatrices
    KeyMatrices.clear();
    for (unsigned r = 0; r <= rounds; ++r) {
        // Create matrix
        std::vector<keyblock> mat;
        // Fill matrix with random bits
        do {
            mat.clear();
            for (unsigned i = 0; i < blocksize; ++i) {
                mat.push_back( getrandkeyblock () );
            }
        // Repeat if matrix is not of maximal rank
        } while ( rank_of_Matrix_Key(mat) < std::min(blocksize, keysize) );
        KeyMatrices.push_back(mat);
    }

    return;
}


// No reference analogue: bit-packs the matrices and constants row-major
// (32 B/row, LSB-first) for the circuit's lowmc_matmul / lowmc_const_block.
void LowMC::flatten () {
    auto pack = [](const block& b, uint8_t* out) {
        std::memset(out, 0, 32);
        for (unsigned i = 0; i < blocksize; ++i) {
            if (b[i]) out[i >> 3] |= uint8_t(1u << (i & 7));
        }
    };

    lin_flat.assign(size_t(rounds) * 256 * 32, 0);
    for (unsigned r = 0; r < rounds; ++r) {
        for (unsigned i = 0; i < 256; ++i) {
            pack(LinMatrices[r][i], &lin_flat[(size_t(r) * 256 + i) * 32]);
        }
    }

    key_flat.assign(size_t(rounds + 1) * 256 * 32, 0);
    for (unsigned r = 0; r <= rounds; ++r) {
        for (unsigned i = 0; i < 256; ++i) {
            pack(KeyMatrices[r][i], &key_flat[(size_t(r) * 256 + i) * 32]);
        }
    }

    rc_flat.assign(size_t(rounds) * 32, 0);
    for (unsigned r = 0; r < rounds; ++r) {
        pack(roundconstants[r], &rc_flat[size_t(r) * 32]);
    }

    return;
}


/////////////////////////////
// Binary matrix functions //
/////////////////////////////


unsigned LowMC::rank_of_Matrix (const std::vector<block> matrix) const {
    std::vector<block> mat; //Copy of the matrix
    for (auto u : matrix) {
        mat.push_back(u);
    }
    unsigned size = mat[0].size();
    //Transform to upper triangular matrix
    unsigned row = 0;
    for (unsigned col = 1; col <= size; ++col) {
        if ( !mat[row][size-col] ) {
            unsigned r = row;
            while (r < mat.size() && !mat[r][size-col]) {
                ++r;
            }
            if (r >= mat.size()) {
                continue;
            } else {
                auto temp = mat[row];
                mat[row] = mat[r];
                mat[r] = temp;
            }
        }
        for (unsigned i = row+1; i < mat.size(); ++i) {
            if ( mat[i][size-col] ) mat[i] ^= mat[row];
        }
        ++row;
        if (row == size) break;
    }
    return row;
}


unsigned LowMC::rank_of_Matrix_Key (const std::vector<keyblock> matrix) const {
    std::vector<keyblock> mat; //Copy of the matrix
    for (auto u : matrix) {
        mat.push_back(u);
    }
    unsigned size = mat[0].size();
    //Transform to upper triangular matrix
    unsigned row = 0;
    for (unsigned col = 1; col <= size; ++col) {
        if ( !mat[row][size-col] ) {
            unsigned r = row;
            while (r < mat.size() && !mat[r][size-col]) {
                ++r;
            }
            if (r >= mat.size()) {
                continue;
            } else {
                auto temp = mat[row];
                mat[row] = mat[r];
                mat[r] = temp;
            }
        }
        for (unsigned i = row+1; i < mat.size(); ++i) {
            if ( mat[i][size-col] ) mat[i] ^= mat[row];
        }
        ++row;
        if (row == size) break;
    }
    return row;
}

// No need for invert_Matrix as decrypt is not used for NIBS

///////////////////////
// Pseudorandom bits //
///////////////////////


std::bitset<80> state; //Keeps the 80 bit LSFR state

// Uses the Grain LSFR as self-shrinking generator to create pseudorandom bits
// Is initialized with the all 1s state
// The first 160 bits are thrown away
bool getrandbit () {
    bool tmp = 0;
    //If state has not been initialized yet
    if (state.none ()) {
        state.set (); //Initialize with all bits set
        //Throw the first 160 bits away
        for (unsigned i = 0; i < 160; ++i) {
            //Update the state
            tmp =  state[0] ^ state[13] ^ state[23]
                       ^ state[38] ^ state[51] ^ state[62];
            state >>= 1;
            state[79] = tmp;
        }
    }
    //choice records whether the first bit is 1 or 0.
    //The second bit is produced if the first bit is 1.
    bool choice = false;
    do {
        //Update the state
        tmp =  state[0] ^ state[13] ^ state[23]
                   ^ state[38] ^ state[51] ^ state[62];
        state >>= 1;
        state[79] = tmp;
        choice = tmp;
        tmp =  state[0] ^ state[13] ^ state[23]
                   ^ state[38] ^ state[51] ^ state[62];
        state >>= 1;
        state[79] = tmp;
    } while (! choice);
    return tmp;
}


block LowMC::getrandblock () const {
    block tmp = 0;
    for (unsigned i = 0; i < blocksize; ++i) tmp[i] = getrandbit ();
    return tmp;
}

keyblock LowMC::getrandkeyblock () const {
    keyblock tmp = 0;
    for (unsigned i = 0; i < keysize; ++i) tmp[i] = getrandbit ();
    return tmp;
}


/////////////////////////////
//   Block <-> byte I/O    //
/////////////////////////////


block load_block (const uint8_t* bytes) {
    block b = 0;
    for (unsigned i = 0; i < blocksize; ++i) {
        if ((bytes[i >> 3] >> (i & 7)) & 1) b[i] = 1;
    }
    return b;
}


void store_block (const block b, uint8_t* bytes) {
    std::memset(bytes, 0, 32);
    for (unsigned i = 0; i < blocksize; ++i) {
        if (b[i]) bytes[i >> 3] |= uint8_t(1u << (i & 7));
    }
}


LowMC* g_lowmc = nullptr;

} // namespace


/////////////////////////////
//    C interface (FFI)    //
/////////////////////////////

extern "C" {

void nibs_lowmc_init (void)
{
    if (g_lowmc) return;
    g_lowmc = new LowMC(NIBS_LOWMC_BOXES, 256, NIBS_LOWMC_PRF_ROUNDS);
}

unsigned nibs_lowmc_rounds (int inst) { (void)inst; return g_lowmc->rounds; }

void nibs_lowmc_encrypt (int inst, const uint8_t* key, const uint8_t* pt, uint8_t* ct)
{
    (void)inst;
    block c = g_lowmc->encrypt(load_block(key), load_block(pt));
    store_block(c, ct);
}

void nibs_lowmc_witness_states (int inst, const uint8_t* key, const uint8_t* pt,
                                uint8_t* states, uint8_t* ct)
{
    (void)inst;
    std::vector<block> post;
    block c = g_lowmc->encrypt(load_block(key), load_block(pt), &post);
    for (unsigned r = 0; r < g_lowmc->rounds; ++r) store_block(post[r], states + size_t(r) * 32);
    if (ct) store_block(c, ct);
}

const uint8_t* nibs_lowmc_linmat (int inst, unsigned r)
{ (void)inst; return &g_lowmc->lin_flat[size_t(r) * 256 * 32]; }

const uint8_t* nibs_lowmc_keymat (int inst, unsigned r)
{ (void)inst; return &g_lowmc->key_flat[size_t(r) * 256 * 32]; }

const uint8_t* nibs_lowmc_roundconst (int inst, unsigned r)
{ (void)inst; return &g_lowmc->rc_flat[size_t(r) * 32]; }


void nibs_lowmc_build_pt (uint8_t dom, const uint8_t* payload16, uint8_t* pt)
{
    std::memset(pt, 0, NIBS_LOWMC_BLOCK_BYTES);
    pt[0] = dom;
    if (payload16) std::memcpy(pt + 1, payload16, 16);
}


// GadA: pkR = Com(skR; open) = E^PRF_skR( PT(DOM_PK, open) )
void nibs_derive_pkr (const uint8_t* skR, const uint8_t* open, uint8_t* pkR)
{
    uint8_t pt[32];
    nibs_lowmc_build_pt(NIBS_DOM_PK, open, pt);
    nibs_lowmc_encrypt(NIBS_LOWMC_PRF, skR, pt, pkR);
}


// GadM: m = E^PRF_skR( PT(DOM_M, nonce) )
void nibs_derive_message (const uint8_t* skR, const uint8_t* nonce, uint8_t* m)
{
    uint8_t pt[32];
    nibs_lowmc_build_pt(NIBS_DOM_M, nonce, pt);
    nibs_lowmc_encrypt(NIBS_LOWMC_PRF, skR, pt, m);
}


// Fills the LowMC region only (896 B): skR | open | nonce | GadA states |
// GadM states.
void nibs_lowmc_witness_expand (const uint8_t* skR, const uint8_t* open,
                                const uint8_t* nonce, uint8_t* out,
                                uint8_t* pkr_out)
{
    uint8_t* p = out;
    std::memcpy(p, skR, 32);   p += 32;
    std::memcpy(p, open, 16);  p += 16;
    std::memcpy(p, nonce, 16); p += 16;

    uint8_t pt[32];

    // GadA: pkR = E^PRF_skR(PT(DOM_PK, open))
    nibs_lowmc_build_pt(NIBS_DOM_PK, open, pt);
    nibs_lowmc_witness_states(NIBS_LOWMC_PRF, skR, pt, p, pkr_out);
    p += NIBS_LOWMC_PRF_ROUNDS * 32;

    // GadM: m = E^PRF_skR(PT(DOM_M, nonce))
    nibs_lowmc_build_pt(NIBS_DOM_M, nonce, pt);
    nibs_lowmc_witness_states(NIBS_LOWMC_PRF, skR, pt, p, nullptr);
}

} // extern "C"

#ifdef LOWMC_PORT_TEST
extern "C" void nibs_lowmc_port_kat (const uint8_t key10[10],
                                     const uint8_t pt32[32], uint8_t ct32[32])
{
    static LowMC* ref = nullptr;
    if (!ref) ref = new LowMC(49, 80, 12);
    keyblock k = 0;
    for (unsigned i = 0; i < 80; ++i) {
        if ((key10[i >> 3] >> (i & 7)) & 1) k[i] = 1;
    }
    store_block(ref->encrypt(k, load_block(pt32)), ct32);
}
#endif
