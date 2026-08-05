#ifndef OWF_PROOF_LOWMC_INC
#define OWF_PROOF_LOWMC_INC

// Single LowMC gadget for Algorithm 2:  m = LowMC_K(r), with K at
// NIBS_K_BIT_OFF, r at NIBS_R_BIT_OFF, post-S-box states at NIBS_GADM_ST_OFF
// and m bound to the PUBLIC statement (pk->msg). Width-generic: everything is
// sized off lowmc_params.hpp, never a literal 256/32.

template <typename QS> using lowmc_bit = quicksilver_gf2<QS, 1>;
template <typename QS>
using lowmc_blk = std::array<lowmc_bit<QS>, NIBS_LOWMC_BLOCK_BITS>;

// --- wire helpers ------------------------------------------------------------
template <typename QS>
static inline lowmc_bit<QS> lowmc_const_bit(QS* qs, int v)
{
    return lowmc_bit<QS>(poly1::load((uint8_t)(v ? 1 : 0), 0), qs);
}

template <typename QS>
static lowmc_blk<QS> lowmc_load_witness_block(QS* qs, size_t bit_off)
{
    lowmc_blk<QS> out;
    for (size_t i = 0; i < NIBS_LOWMC_BLOCK_BITS; ++i)
        out[i] = qs->get_witness_bit(bit_off + i);
    return out;
}

template <typename QS>
static lowmc_blk<QS> lowmc_const_block(QS* qs,
                                       const uint8_t bytes[NIBS_LOWMC_BLOCK_BYTES])
{
    lowmc_blk<QS> out;
    for (size_t i = 0; i < NIBS_LOWMC_BLOCK_BITS; ++i)
        out[i] = lowmc_const_bit(qs, (bytes[i >> 3] >> (i & 7)) & 1);
    return out;
}

template <typename QS>
static lowmc_blk<QS> lowmc_matmul(QS* qs, const uint8_t* rows,
                                  const lowmc_blk<QS>& in)
{
    lowmc_blk<QS> out;
    for (size_t i = 0; i < NIBS_LOWMC_BLOCK_BITS; ++i) {
        lowmc_bit<QS> acc = lowmc_const_bit(qs, 0);
        const uint8_t* row = rows + i * NIBS_LOWMC_ROW_BYTES;
        for (size_t byte = 0; byte < NIBS_LOWMC_ROW_BYTES; ++byte) {
            uint8_t b = row[byte];
            while (b) {
                unsigned j = (unsigned)__builtin_ctz(b);
                acc = acc + in[byte * 8 + j];
                b &= (uint8_t)(b - 1);
            }
        }
        out[i] = acc;
    }
    return out;
}

template <typename QS>
static inline void lowmc_xor_inplace(lowmc_blk<QS>& a, const lowmc_blk<QS>& b)
{
    for (size_t i = 0; i < NIBS_LOWMC_BLOCK_BITS; ++i) a[i] = a[i] + b[i];
}

// --- the LowMC gadget --------------------------------------------------------
template <typename QS>
static lowmc_blk<QS> lowmc_gadget(QS* qs, const lowmc_blk<QS>& key,
                                  const lowmc_blk<QS>& pt, size_t st_bit_off)
{
    lowmc_blk<QS> state = lowmc_matmul(qs, nibs_lowmc_keymat(0), key);
    lowmc_xor_inplace(state, pt);

    for (unsigned r = 1; r <= NIBS_LOWMC_ROUNDS; ++r) {
        lowmc_blk<QS> y = lowmc_load_witness_block(
            qs, st_bit_off + size_t(r - 1) * NIBS_LOWMC_BLOCK_BITS);

        // S-box constraints
        for (unsigned j = 0; j < NIBS_LOWMC_BOXES; ++j) {
            const auto& c_in = state[3 * j + 0];
            const auto& b_in = state[3 * j + 1];
            const auto& a_in = state[3 * j + 2];
            const auto& z_o  = y[3 * j + 0];
            const auto& y_o  = y[3 * j + 1];
            const auto& x_o  = y[3 * j + 2];

            quicksilver_gfsecpar<QS, 1> A(a_in), B(b_in), C(c_in);
            quicksilver_gfsecpar<QS, 1> X(x_o), Y(y_o), Z(z_o);

            // x = a + b*c ; y = a + b + a*c ; z = a + b + c + a*b
            qs->add_constraint(B * C + quicksilver_gfsecpar<QS, 2>(X + A));
            qs->add_constraint(A * C + quicksilver_gfsecpar<QS, 2>(Y + A + B));
            qs->add_constraint(A * B +
                               quicksilver_gfsecpar<QS, 2>(Z + A + B + C));
        }
        // identity bits (top of the block) pass through unchanged
        for (unsigned i = 3 * NIBS_LOWMC_BOXES; i < NIBS_LOWMC_BLOCK_BITS; ++i)
            qs->add_constraint(quicksilver_gfsecpar<QS, 2>(
                quicksilver_gfsecpar<QS, 1>(y[i]) +
                quicksilver_gfsecpar<QS, 1>(state[i])));

        // in_{r+1} (or the output after the last round):
        //   L_{r-1} * y  ^  C_{r-1}  ^  RK_r
        state = lowmc_matmul(qs, nibs_lowmc_linmat(r - 1), y);
        lowmc_blk<QS> rc = lowmc_const_block(qs, nibs_lowmc_roundconst(r - 1));
        lowmc_xor_inplace(state, rc);
        lowmc_blk<QS> rk = lowmc_matmul(qs, nibs_lowmc_keymat(r), key);
        lowmc_xor_inplace(state, rk);
    }
    return state;
}

template <typename QS, typename P>
static void nibs_lowmc_constraints(QS* qs, const public_key<P>* pk)
{
    nibs_lowmc_init();

    // ---- witness wires: K and r (shared with the Rain gadgets) --------------
    lowmc_blk<QS> K = lowmc_load_witness_block(qs, NIBS_K_BIT_OFF);
    lowmc_blk<QS> r = lowmc_load_witness_block(qs, NIBS_R_BIT_OFF);

    // ---- GadM: m = LowMC_K(r), r is the plaintext block verbatim ------------
    lowmc_blk<QS> m_wires = lowmc_gadget(qs, K, r, NIBS_GADM_ST_OFF);

    // ---- m is PUBLIC: bind the final state to the statement -----------------
    const uint8_t* m_pub = (const uint8_t*)&pk->msg;
    for (size_t i = 0; i < NIBS_M_BITS; ++i) {
        int pub = (m_pub[i >> 3] >> (i & 7)) & 1;
        qs->add_constraint(quicksilver_gfsecpar<QS, 2>(
            quicksilver_gfsecpar<QS, 1>(m_wires[i]) +
            quicksilver_gfsecpar<QS, 1>(lowmc_const_bit(qs, pub))));
    }
}

#endif // OWF_PROOF_LOWMC_INC
