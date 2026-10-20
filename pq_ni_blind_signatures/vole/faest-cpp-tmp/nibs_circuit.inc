// nibs_circuit.inc -- the NIBS relation as VOLEitH/QuickSilver constraints.
//
// Gadgets work on *wires* (quicksilver_gf2 values of degree 1, i.e. affine
// functions of the committed witness). Only non-linear intermediate values
// are committed: the post-S-box states of LowMC and of RainHash. Inputs and
// outputs of every gadget are computed as wires, so the witness carries no
// copies and no seam constraints are needed.
//
// Included from owf_proof.inc inside namespace faest.

#ifndef NIBS_CIRCUIT_INC
#define NIBS_CIRCUIT_INC

// Requires (included by owf_proof.inc outside the namespace):
//   lowmc_plain/lowmc.hpp, rain_tower_tables.hpp, rainhash_plain/rain_hash.h

template <typename QS> using nibs_bit = quicksilver_gf2<QS, 1>;
template <typename QS> using nibs_val = quicksilver_gfsecpar<QS, 1>;
template <typename QS> using nibs_val2 = quicksilver_gfsecpar<QS, 2>;
template <typename QS> using nibs_wires = std::vector<nibs_bit<QS>>;

template <typename QS> static inline nibs_bit<QS> nibs_zero_wire(const QS* qs)
{
    return nibs_bit<QS>(qs);
}

template <typename QS> static inline nibs_bit<QS> nibs_const_wire(const QS* qs, int v)
{
    return nibs_bit<QS>(poly1::load(v ? 1 : 0, 0), qs);
}

template <typename QS> static nibs_wires<QS> nibs_witness_wires(const QS* qs, size_t off, size_t n)
{
    nibs_wires<QS> out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i)
        out.push_back(qs->get_witness_bit(off + i));
    return out;
}

// Wires holding the constant bit string `bytes` (n bits).
template <typename QS>
static nibs_wires<QS> nibs_const_wires(const QS* qs, const uint8_t* bytes, size_t n)
{
    nibs_wires<QS> out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i)
        out.push_back(nibs_const_wire(qs, (bytes[i >> 3] >> (i & 7)) & 1));
    return out;
}

// x == y as n bit constraints (x + y lifted to degree 2).
template <typename QS>
static void nibs_assert_bits_equal_const(QS* qs, const nibs_bit<QS>* x, const uint8_t* bytes,
                                         size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        nibs_bit<QS> d = x[i] + poly1::load((bytes[i >> 3] >> (i & 7)) & 1, 0);
        qs->add_constraint(nibs_val2<QS>(nibs_val<QS>(d)));
    }
}

// sum_b table[b] * bits[b] for constant field elements table[b] (an F_2-linear
// map from n wires into F_{2^lambda}).
template <typename QS>
static nibs_val<QS> nibs_combine_table(const nibs_bit<QS>* bits, size_t n,
                                       const poly_secpar<QS::secpar_v>* table)
{
    constexpr secpar S = QS::secpar_v;
    constexpr size_t B = secpar_to_bits(S);
    nibs_val<QS> out(poly1::set_zero(), bits[0]);
    if constexpr (!QS::is_verifier)
    {
        auto acc = poly_2secpar<S>::set_zero();
        auto val = poly_secpar<S>::set_zero();
        for (size_t b = 0; b < n; ++b)
        {
            acc += table[b] * bits[b].mac.coeffs[0];
            if (bits[b].value().data)
                val += table[b];
        }
        out.mac.coeffs[0] = acc.template reduce_to<B>();
        out.value() = val;
    }
    else
    {
        auto acc = poly_2secpar<S>::set_zero();
        for (size_t b = 0; b < n; ++b)
            acc += table[b] * bits[b].mac;
        out.mac = acc.template reduce_to<B>();
    }
    return out;
}

// out[i] = sum_j row_i[j] in[j]; rows are row-major, row_bytes per row.
template <typename QS>
static nibs_wires<QS> nibs_matmul_rows(const QS* qs, const uint8_t* rows, size_t row_bytes,
                                       size_t n_out, const nibs_wires<QS>& in)
{
    nibs_wires<QS> out(n_out, nibs_zero_wire(qs));
    for (size_t i = 0; i < n_out; ++i)
    {
        nibs_bit<QS> acc = nibs_zero_wire(qs);
        const uint8_t* row = rows + i * row_bytes;
        for (size_t byte = 0; byte < row_bytes; ++byte)
        {
            uint8_t b = row[byte];
            while (b)
            {
                unsigned j = (unsigned)__builtin_ctz(b);
                acc = acc + in[byte * 8 + j];
                b &= (uint8_t)(b - 1);
            }
        }
        out[i] = acc;
    }
    return out;
}

// ===========================================================================
// LowMC gadget (level-generic). Commits ROUNDS post-S-box states at st_off.
// ===========================================================================

template <typename QS, unsigned LEVEL>
static nibs_wires<QS> nibs_lowmc_gadget(QS* qs, const nibs_wires<QS>& key,
                                        const nibs_wires<QS>& pt, size_t st_off)
{
    using D = nibs_lowmc::derived<LEVEL>;
    constexpr size_t N = D::BLOCK_BITS;
    constexpr size_t NB = D::BLOCK_BYTES;

    nibs_wires<QS> state = nibs_matmul_rows(qs, nibs_lowmc::keymat<LEVEL>(0), NB, N, key);
    for (size_t i = 0; i < N; ++i)
        state[i] = state[i] + pt[i];

    for (unsigned r = 1; r <= D::ROUNDS; ++r)
    {
        nibs_wires<QS> y = nibs_witness_wires(qs, st_off + size_t(r - 1) * N, N);

        // S-box (c, b, a) -> (z, y, x):  x = a + bc, y = a + b + ac, z = a + b + c + ab
        for (unsigned j = 0; j < D::BOXES; ++j)
        {
            nibs_val<QS> C(state[3 * j + 0]), Bv(state[3 * j + 1]), A(state[3 * j + 2]);
            nibs_val<QS> Z(y[3 * j + 0]), Y(y[3 * j + 1]), X(y[3 * j + 2]);
            qs->add_constraint(Bv * C + nibs_val2<QS>(X + A));
            qs->add_constraint(A * C + nibs_val2<QS>(Y + A + Bv));
            qs->add_constraint(A * Bv + nibs_val2<QS>(Z + A + Bv + C));
        }
        for (size_t i = 3 * D::BOXES; i < N; ++i) // identity part
            qs->add_constraint(nibs_val2<QS>(nibs_val<QS>(y[i]) + nibs_val<QS>(state[i])));

        state = nibs_matmul_rows(qs, nibs_lowmc::linmat<LEVEL>(r - 1), NB, N, y);
        const uint8_t* rc = nibs_lowmc::roundconst<LEVEL>(r - 1);
        nibs_wires<QS> rk = nibs_matmul_rows(qs, nibs_lowmc::keymat<LEVEL>(r), NB, N, key);
        for (size_t i = 0; i < N; ++i)
            state[i] = (state[i] + rk[i]) + poly1::load((rc[i >> 3] >> (i & 7)) & 1, 0);
    }
    return state;
}

// ===========================================================================
// RainHash-512 S-box check in the tower F_{2^128}[X]/(X^4 + a^123 X^2 + X + 1)
// ===========================================================================
//
// A 512-bit Rain state is four 128-bit lanes. Each lane is an element of
// F_{2^128} = F_2[a]/(a^128 + a^7 + a^2 + a + 1), lifted into the VOLEitH
// field as LANE_COORDS coordinates (see rain_tower_tables.hpp):
//   lambda = 128: the lane itself (same modulus as the VOLE field);
//   lambda = 256: the image under F_{2^128} -> F_{2^256};
//   lambda = 192: (A, B) with lane = A + B*a, A, B in F_{2^64} -> F_{2^192}.
// The S-box is x -> x^{-1}; we check in * out == 1 coefficient-wise.

template <secpar S> struct nibs_rain_lane_tables
{
    static constexpr size_t D = (S == secpar::s192) ? 2 : 1;
    std::array<std::array<poly_secpar<S>, 128>, D> emb; // emb[c][b]: coordinate c of a^b
    std::array<poly_secpar<S>, D> a123;                 // the constant a^123
    poly_secpar<S> c0, c1;                              // a^2 = c1 a + c0 (D = 2 only)
    std::array<poly_secpar<S>, D> one;

    nibs_rain_lane_tables()
    {
        for (size_t b = 0; b < 128; ++b)
        {
            if constexpr (S == secpar::s128)
            {
                uint8_t bytes[16] = {0};
                bytes[b / 8] = uint8_t(1u << (b % 8));
                emb[0][b] = poly_secpar<S>::load_dup(bytes);
            }
            else if constexpr (S == secpar::s256)
                emb[0][b] = poly_secpar<S>::load_dup(RAIN_LANE_EMB_256[b]);
            else
            {
                emb[0][b] = poly_secpar<S>::load_dup(RAIN_LANE_EMB_192_A[b]);
                emb[1][b] = poly_secpar<S>::load_dup(RAIN_LANE_EMB_192_B[b]);
            }
        }
        for (size_t c = 0; c < D; ++c)
        {
            a123[c] = emb[c][123];
            one[c] = c == 0 ? emb[0][0] : poly_secpar<S>::set_zero();
        }
        if constexpr (D == 2)
        {
            c0 = poly_secpar<S>::load_dup(RAIN_LANE_192_C0);
            c1 = poly_secpar<S>::load_dup(RAIN_LANE_192_C1);
        }
    }

    static const nibs_rain_lane_tables& get()
    {
        static const nibs_rain_lane_tables t;
        return t;
    }
};

template <secpar S> static inline poly_secpar<S> nibs_pmul(const poly_secpar<S>& a, const poly_secpar<S>& b)
{
    return (a * b).template reduce_to<secpar_to_bits(S)>();
}

template <typename QS> struct nibs_lane
{
    static constexpr secpar S = QS::secpar_v;
    static constexpr size_t D = nibs_rain_lane_tables<S>::D;
    template <size_t deg> using lane = std::array<quicksilver_gfsecpar<QS, deg>, D>;

    static lane<1> from_bits(const nibs_bit<QS>* bits)
    {
        lane<1> out;
        if constexpr (S == secpar::s128)
            out[0] = nibs_val<QS>::combine_128_bits(bits);
        else
        {
            const auto& T = nibs_rain_lane_tables<S>::get();
            for (size_t c = 0; c < D; ++c)
                out[c] = nibs_combine_table<QS>(bits, 128, T.emb[c].data());
        }
        return out;
    }

    template <size_t da, size_t db>
    static lane<da + db> mul(const lane<da>& x, const lane<db>& y)
    {
        lane<da + db> out;
        if constexpr (D == 1)
            out[0] = x[0] * y[0];
        else
        {
            const auto& T = nibs_rain_lane_tables<S>::get();
            auto bb = x[1] * y[1];
            out[0] = x[0] * y[0] + T.c0 * bb;
            out[1] = x[0] * y[1] + x[1] * y[0] + T.c1 * bb;
        }
        return out;
    }

    template <size_t d> static lane<d> scale(const lane<d>& x, const std::array<poly_secpar<S>, D>& k)
    {
        lane<d> out;
        if constexpr (D == 1)
            out[0] = k[0] * x[0];
        else
        {
            const auto& T = nibs_rain_lane_tables<S>::get();
            // (P + Q a)(Ac + Bc a) = (P Ac + Q c0 Bc) + (P Bc + Q (Ac + c1 Bc)) a
            const poly_secpar<S> k1 = nibs_pmul<S>(T.c0, k[1]);
            const poly_secpar<S> k2 = k[0] + nibs_pmul<S>(T.c1, k[1]);
            out[0] = k[0] * x[0] + k1 * x[1];
            out[1] = k[1] * x[0] + k2 * x[1];
        }
        return out;
    }

    template <size_t d> static lane<d> add(const lane<d>& x, const lane<d>& y)
    {
        lane<d> out;
        for (size_t c = 0; c < D; ++c)
            out[c] = x[c] + y[c];
        return out;
    }
};

// Constraints: lanes(in) * lanes(out) == 1 in the tower. 4 * D constraints.
template <typename QS>
static void nibs_rain_sbox_check(QS* qs, const nibs_wires<QS>& in, const nibs_wires<QS>& out)
{
    using LN = nibs_lane<QS>;
    constexpr size_t D = LN::D;
    const auto& T = nibs_rain_lane_tables<QS::secpar_v>::get();

    typename LN::template lane<1> a[4], b[4];
    for (size_t i = 0; i < 4; ++i)
    {
        a[i] = LN::from_bits(&in[128 * i]);
        b[i] = LN::from_bits(&out[128 * i]);
    }

    typename LN::template lane<2> c[7];
    bool set[7] = {false};
    for (size_t i = 0; i < 4; ++i)
        for (size_t j = 0; j < 4; ++j)
        {
            auto p = LN::template mul<1, 1>(a[i], b[j]);
            c[i + j] = set[i + j] ? LN::add(c[i + j], p) : p;
            set[i + j] = true;
        }
    // X^4 = a^123 X^2 + X + 1
    for (int k = 6; k >= 4; --k)
    {
        c[k - 2] = LN::add(c[k - 2], LN::scale(c[k], T.a123));
        c[k - 3] = LN::add(c[k - 3], c[k]);
        c[k - 4] = LN::add(c[k - 4], c[k]);
    }
    for (size_t k = 0; k < 4; ++k)
        for (size_t cc = 0; cc < D; ++cc)
        {
            if (k == 0 && cc == 0)
                qs->add_constraint(c[0][0] + poly1::set_one());
            else
                qs->add_constraint(c[k][cc]);
        }
}

// ===========================================================================
// RainHash-512 gadget: out = pi(in) + in, 7 rounds of
//   x <- M_r * (x + rc_r)^{-1}. Commits the 7 S-box outputs at st_off.
// ===========================================================================

template <typename QS>
static nibs_wires<QS> nibs_rain_gadget(QS* qs, const nibs_wires<QS>& in, size_t st_off)
{
    constexpr size_t B = VOLERAINHASH_B;
    nibs_wires<QS> x = in;
    for (size_t r = 0; r < VOLERAINHASH_NUM_ROUNDS; ++r)
    {
        const uint8_t* rc = reinterpret_cast<const uint8_t*>(rain_roundconst[r].data());
        nibs_wires<QS> sin(B, nibs_zero_wire(qs));
        for (size_t i = 0; i < B; ++i)
            sin[i] = x[i] + poly1::load((rc[i >> 3] >> (i & 7)) & 1, 0);
        nibs_wires<QS> sout = nibs_witness_wires(qs, st_off + B * r, B);
        nibs_rain_sbox_check(qs, sin, sout);
        // Rain matrices are stored per output bit: 64 bytes per output.
        const uint8_t* mat = reinterpret_cast<const uint8_t*>(rain_matrix[r].data());
        x = nibs_matmul_rows(qs, mat, B / 8, B, sout);
    }
    for (size_t i = 0; i < B; ++i)
        x[i] = x[i] + in[i];
    return x;
}

// The target mode T of nibs_target.hpp, on wires. Returns T_BYTES*8 wires.
template <typename QS, typename LAY>
static nibs_wires<QS> nibs_target_wires(QS* qs, const nibs_wires<QS>& msg)
{
    constexpr size_t B = VOLERAINHASH_B;
    constexpr size_t RATE = 8 * nibs_level<QS::secpar_v>::RATE_BYTES;
    const size_t len = msg.size();
    size_t gadget = 0;
    auto next_off = [&]() { return LAY::T_OFF + NIBS_RAIN_STATE_BITS * (gadget++); };

    nibs_wires<QS> blk(B, nibs_const_wire(qs, 1));
    const size_t first = std::min(B, len);
    for (size_t i = 0; i < first; ++i)
        blk[i] = msg[i];
    nibs_wires<QS> h = nibs_rain_gadget(qs, blk, next_off());
    for (size_t pos = first; pos < len; pos += RATE)
    {
        const size_t n = std::min(RATE, len - pos);
        for (size_t i = 0; i < B; ++i)
            blk[i] = (i < n) ? (h[i] + msg[pos + i]) : (h[i] + poly1::set_one());
        h = nibs_rain_gadget(qs, blk, next_off());
    }
    nibs_wires<QS> t(h.begin(), h.begin() + std::min(B, 8 * LAY::T_BYTES));
    if constexpr (LAY::T_SQUEEZE_BLOCKS)
    {
        nibs_wires<QS> h2 = nibs_rain_gadget(qs, h, next_off());
        t.insert(t.end(), h2.begin(), h2.begin() + (8 * LAY::T_BYTES - B));
    }
    FAEST_ASSERT(gadget == LAY::T_BLOCKS);
    return t;
}

#endif // NIBS_CIRCUIT_INC
