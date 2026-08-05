#ifndef OWF_PROOF_LOWMC_INC
#define OWF_PROOF_LOWMC_INC

template <typename QS> using lowmc_bit  = quicksilver_gf2<QS, 1>;
template <typename QS> using lowmc_blk  = std::array<lowmc_bit<QS>, 256>;

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
    for (size_t i = 0; i < 256; ++i)
        out[i] = qs->get_witness_bit(bit_off + i);
    return out;
}

template <typename QS>
static lowmc_blk<QS> lowmc_const_block(QS* qs, const uint8_t bytes[32])
{
    lowmc_blk<QS> out;
    for (size_t i = 0; i < 256; ++i)
        out[i] = lowmc_const_bit(qs, (bytes[i >> 3] >> (i & 7)) & 1);
    return out;
}

// PT = [dom, payload(128 bits of wires), zeros].
template <typename QS>
static lowmc_blk<QS> lowmc_pt_block(QS* qs, uint8_t dom,
                                    const lowmc_bit<QS>* payload128)
{
    lowmc_blk<QS> out;
    for (size_t i = 0; i < 8; ++i)
        out[i] = lowmc_const_bit(qs, (dom >> i) & 1);
    for (size_t i = 0; i < 128; ++i)
        out[8 + i] = payload128 ? payload128[i] : lowmc_const_bit(qs, 0);
    for (size_t i = 136; i < 256; ++i)
        out[i] = lowmc_const_bit(qs, 0);
    return out;
}

template <typename QS>
static lowmc_blk<QS> lowmc_matmul(QS* qs, const uint8_t* rows,
                                  const lowmc_blk<QS>& in)
{
    lowmc_blk<QS> out;
    for (size_t i = 0; i < 256; ++i) {
        lowmc_bit<QS> acc = lowmc_const_bit(qs, 0);
        const uint8_t* row = rows + i * 32;
        for (size_t byte = 0; byte < 32; ++byte) {
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
    for (size_t i = 0; i < 256; ++i) a[i] = a[i] + b[i];
}

template <typename QS>
static inline void lowmc_bind_wire_to_witness(QS* qs,
                                              const lowmc_bit<QS>& wire,
                                              size_t witness_bit_off)
{
    lowmc_bit<QS> w = qs->get_witness_bit(witness_bit_off);
    qs->add_constraint(quicksilver_gfsecpar<QS, 2>(
        quicksilver_gfsecpar<QS, 1>(wire) +
        quicksilver_gfsecpar<QS, 1>(w)));
}

// --- the LowMC gadget ---------------------------------------------------------
template <typename QS>
static lowmc_blk<QS> lowmc_gadget(QS* qs, int inst,
                                  const lowmc_blk<QS>& key,
                                  const lowmc_blk<QS>& pt,
                                  size_t st_bit_off)
{
    const unsigned R = nibs_lowmc_rounds(inst);

    lowmc_blk<QS> state = lowmc_matmul(qs, nibs_lowmc_keymat(inst, 0), key);
    lowmc_xor_inplace(state, pt);

    for (unsigned r = 1; r <= R; ++r) {
        lowmc_blk<QS> y =
            lowmc_load_witness_block(qs, st_bit_off + size_t(r - 1) * 256);

        // S-box constraints
        for (unsigned j = 0; j < NIBS_LOWMC_BOXES_C; ++j) {
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
        // identity bit (bit 255) passes through the S-box layer unchanged
        qs->add_constraint(quicksilver_gfsecpar<QS, 2>(
            quicksilver_gfsecpar<QS, 1>(y[255]) +
            quicksilver_gfsecpar<QS, 1>(state[255])));

        // in_{r+1} (or the output after the last round):
        //   L_{r-1} * y  ^  C_{r-1}  ^  RK_r
        state = lowmc_matmul(qs, nibs_lowmc_linmat(inst, r - 1), y);
        lowmc_blk<QS> rc =
            lowmc_const_block(qs, nibs_lowmc_roundconst(inst, r - 1));
        lowmc_xor_inplace(state, rc);
        lowmc_blk<QS> rk = lowmc_matmul(qs, nibs_lowmc_keymat(inst, r), key);
        lowmc_xor_inplace(state, rk);
    }
    return state;
}

template <typename QS, typename P>
static void nibs_lowmc_constraints(QS* qs, const public_key<P>* pk)
{
    nibs_lowmc_init();

    // ---- witness wires -------------------------------------------------------
    lowmc_blk<QS> skR = lowmc_load_witness_block(qs, NIBS_SKR_BIT_OFF);

    std::array<lowmc_bit<QS>, 128> open, nonce;
    for (size_t i = 0; i < 128; ++i) {
        open[i]  = qs->get_witness_bit(NIBS_OPEN_BIT_OFF + i);
        nonce[i] = qs->get_witness_bit(NIBS_NONCE_BIT_OFF + i);
    }

    // ---- GadA: pkR = E^PRF_skR(PT(DOM_PK, open)) ------------------------------
    lowmc_blk<QS> pt_pk = lowmc_pt_block<QS>(qs, NIBS_DOM_PK_C, open.data());
    lowmc_blk<QS> pkR =
        lowmc_gadget(qs, NIBS_LOWMC_PRF, skR, pt_pk, NIBS_GADA_ST_OFF);

    // ---- seam: bind Rain block B1's witnessed message lanes -------------------
    for (size_t i = 0; i < 256; ++i)
        lowmc_bind_wire_to_witness(qs, pkR[i], NIBS_GAD2_B1_BIT_OFF + i);

    for (size_t i = 0; i < 128; ++i)
        lowmc_bind_wire_to_witness(qs, nonce[i],
                                   NIBS_GAD2_B1_BIT_OFF + 256 + i);

    // ---- GadM: m = E^PRF_skR(PT(DOM_M, nonce)), constrained to PUBLIC m -------
    lowmc_blk<QS> pt_m = lowmc_pt_block<QS>(qs, NIBS_DOM_M_C, nonce.data());
    lowmc_blk<QS> m_wires =
        lowmc_gadget(qs, NIBS_LOWMC_PRF, skR, pt_m, NIBS_GADM_ST_OFF);
    const uint8_t* m_pub = (const uint8_t*)&pk->msg;
    for (size_t i = 0; i < 256; ++i) {
        int pub = (m_pub[i >> 3] >> (i & 7)) & 1;
        qs->add_constraint(quicksilver_gfsecpar<QS, 2>(
            quicksilver_gfsecpar<QS, 1>(m_wires[i]) +
            quicksilver_gfsecpar<QS, 1>(lowmc_const_bit(qs, pub))));
    }
}

#endif // OWF_PROOF_LOWMC_INC
