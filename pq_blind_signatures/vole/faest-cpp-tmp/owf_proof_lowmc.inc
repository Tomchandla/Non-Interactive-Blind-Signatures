// owf_proof_lowmc.inc
//
// LowMC replacement for the four RainHash gadgets (RainA, Rain1, Rain2,
// RainM) in owf_proof.inc. Include from owf_proof.inc and call
// nibs_lowmc_constraints() from owf_constraints() in place of the Rain
// gadget chain; the MAYO section at the bottom is adapted from the existing
// enc_constraints (t becomes a wire expression instead of a witness load).
//
// DESIGN
// ------
// Everything is GF(2) wires (quicksilver_gf2<QS, 1>). Per LowMC round r we
// witness the full 256-bit POST-S-BOX state y_r; every other value --
// round keys, linear-layer outputs, pkR, com, t, m -- is a degree-1 linear
// expression over {witness bits, constants} and is never witnessed. The
// constraint set per round is:
//
//   for each of the 85 S-boxes, inputs (a,b,c) = bits (3j+2, 3j+1, 3j) of
//   the round-input expression, outputs (x,y,z) = the same bits of y_r:
//       x + a + b*c             = 0        (deg 2)
//       y + a + b + a*c         = 0        (deg 2)
//       z + a + b + c + a*b     = 0        (deg 2)
//   identity bit:  y_r[255] + in_r[255] = 0    (deg 1)
//
// with in_1 = pt ^ RK_0 and in_{r+1} = L_r * y_r ^ C_r ^ RK_r, and the
// gadget output out = L_R * y_R ^ C_{R-1..} ^ RK_R exactly mirroring
// lowmc_plain's encrypt() (KAT'd against the reference implementation).
//
// BINDING IS STRUCTURAL: GadA and GadM take the same skR wires as cipher
// key; Gad1 takes GadA's output expression (pkR) as key; Gad2 takes Gad1's
// MMO output (com) as key; the MAYO target is Gad2's MMO output (t). No
// equality constraints, no shared-offset bookkeeping.
//
// COMPILE NOTES (things that may need touching up against your exact
// template set -- see INTEGRATION.md item 4):
//   * constants are built as quicksilver_gf2<QS, 1>(poly1::load(byte, bit),
//     qs_state); if your tree only has the deg-0 constant ctor, construct at
//     deg 0 and rely on the deg-promotion ctor.
//   * degree promotion into add_constraint follows the same pattern as the
//     existing `add_constraint(x * y + 1)` inverse checks.

#ifndef OWF_PROOF_LOWMC_INC
#define OWF_PROOF_LOWMC_INC

// Spliced into owf_proof.inc INSIDE namespace faest, after the Rain gadget
// machinery. Depends on: parameters.hpp (incl. parameters_lowmc.hpp),
// quicksilver.hpp, lowmc_plain/lowmc.hpp, <array>, <vector> -- all included
// by owf_proof.inc before the namespace opens.

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

// Block of constants from 32 bytes (LSB-first packing, as everywhere).
template <typename QS>
static lowmc_blk<QS> lowmc_const_block(QS* qs, const uint8_t bytes[32])
{
    lowmc_blk<QS> out;
    for (size_t i = 0; i < 256; ++i)
        out[i] = lowmc_const_bit(qs, (bytes[i >> 3] >> (i & 7)) & 1);
    return out;
}

// PT = [dom, payload(128 bits of wires), zeros]. payload may be nullptr.
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

// out = M * in, M given as 256 bit-packed rows of 32 bytes. Row i's set
// bits select which input wires XOR into output bit i. Linear over wires:
// no constraints, no degree change.
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

// --- the LowMC gadget ---------------------------------------------------------
//
// key / pt are 256-wire blocks (witness bits, constants, or outputs of an
// earlier gadget). st_bit_off points at rounds(inst) * 256 witnessed
// post-S-box bits. Returns the ciphertext as a wire block.

template <typename QS>
static lowmc_blk<QS> lowmc_gadget(QS* qs, int inst,
                                  const lowmc_blk<QS>& key,
                                  const lowmc_blk<QS>& pt,
                                  size_t st_bit_off)
{
    const unsigned R = nibs_lowmc_rounds(inst);

    // in_1 = pt ^ RK_0
    lowmc_blk<QS> state = lowmc_matmul(qs, nibs_lowmc_keymat(inst, 0), key);
    lowmc_xor_inplace(state, pt);

    for (unsigned r = 1; r <= R; ++r) {
        lowmc_blk<QS> y =
            lowmc_load_witness_block(qs, st_bit_off + size_t(r - 1) * 256);

        // S-box constraints. Bit order inside box j (matches the reference
        // Substitution and the plain-side self-test): c = 3j, b = 3j+1,
        // a = 3j+2. Same positions in y for (z, y, x).
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
    return state; // ciphertext expression
}

// --- full NIBS constraint system ----------------------------------------------
//
// Mixed circuit, matching parameters_lowmc.hpp:
//
//   GadA (LowMC PRF)  : pkR = E^PRF_skR( PT(DOM_PK, open) )
//   Gad1 (LowMC MMO)  : com = MMO(pkR, PT(DOM_COM, nonce))
//   seam              : witnessed Gad2 in-block bits [0,256) == com wires
//   GadM (LowMC PRF)  : m   = E^PRF_skR( PT(DOM_M, nonce) ), m PUBLIC
//   Gad2 (Rain)       : t   = Rain(com | salt | cap)   -- NOT here; proven by
//                       enc_constraints_rainhash in owf_proof.inc on the
//                       in-block this function just bound to com
//   MAYO              : T*(s) = t                      -- NOT here; proven by
//                       enc_constraints_mayo, which reads t from Gad2's
//                       out-block at NIBS_GADGET_2_OUT_OFF
//
// The public m lives in pk->msg (32 bytes; HASHED_MSG_SIZE_BITS == 256).
//
// Constraint count (keep constants.hpp's formula in sync):
//   GadA 13*256 + Gad1 22*256 + GadM 13*256 = 12288
//   seam 256, m-public 256                  ->  12800 total from this fn.

template <typename QS, typename P>
static void nibs_lowmc_constraints(QS* qs, const public_key<P>* pk)
{
    nibs_lowmc_init(); // idempotent

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

    // ---- Gad1: com = E^HASH_pkR(PT(DOM_COM, nonce)) ^ PT (MMO) ----------------
    lowmc_blk<QS> pt_com = lowmc_pt_block<QS>(qs, NIBS_DOM_COM_C, nonce.data());
    lowmc_blk<QS> com =
        lowmc_gadget(qs, NIBS_LOWMC_HASH, pkR, pt_com, NIBS_GAD1_ST_OFF);
    lowmc_xor_inplace(com, pt_com); // MMO feed-forward

    // ---- seam: bind Rain Gad2's witnessed input lanes 0-1 to com --------------
    // enc_constraints_rainhash loads Gad2's com lanes with
    // load_witness_128_bits_and_combine at NIBS_GAD2_COM_BIT_OFF; without these
    // 256 equalities those bits would be a free witness and t would be
    // unbound from (skR, open, nonce).
    for (size_t i = 0; i < 256; ++i) {
        lowmc_bit<QS> w = qs->get_witness_bit(NIBS_GAD2_COM_BIT_OFF + i);
        qs->add_constraint(quicksilver_gfsecpar<QS, 2>(
            quicksilver_gfsecpar<QS, 1>(com[i]) +
            quicksilver_gfsecpar<QS, 1>(w)));
    }

    // ---- GadM: m = E^PRF_skR(PT(DOM_M, nonce)), constrained to PUBLIC m -------
    lowmc_blk<QS> pt_m = lowmc_pt_block<QS>(qs, NIBS_DOM_M_C, nonce.data());
    lowmc_blk<QS> m_wires =
        lowmc_gadget(qs, NIBS_LOWMC_PRF, skR, pt_m, NIBS_GADM_ST_OFF);
    const uint8_t* m_pub = (const uint8_t*)&pk->msg;   // NIBS_M_BYTES long
    for (size_t i = 0; i < 256; ++i) {
        int pub = (m_pub[i >> 3] >> (i & 7)) & 1;
        qs->add_constraint(quicksilver_gfsecpar<QS, 2>(
            quicksilver_gfsecpar<QS, 1>(m_wires[i]) +
            quicksilver_gfsecpar<QS, 1>(lowmc_const_bit(qs, pub))));
    }
}

#endif // OWF_PROOF_LOWMC_INC
