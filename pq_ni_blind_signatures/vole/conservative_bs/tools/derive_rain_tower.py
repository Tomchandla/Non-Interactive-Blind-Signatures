#!/usr/bin/env python3
"""Derive the constants that let the RainHash-512 S-box check run inside the
VOLEitH field at NIST levels 3 and 5.

Background
----------
The plain RainHash-512 implementation (rainhash_plain/field.h) computes the
S-box x -> x^{-1} in the tower field

    F_{2^512} = F_{2^128}[X] / (X^4 + a^123 X^2 + X + 1),
    F_{2^128} = F_2[a]  / (a^128 + a^7 + a^2 + a + 1),

with a 512-bit state laid out as four 128-bit lanes (coefficients of
1, X, X^2, X^3).  The level-1 circuit lifts each lane straight into the
VOLEitH field F_{2^128}, which uses the same modulus, so a lane *is* a field
element.  That does not work at the other levels:

  * lambda = 256: F_{2^128} is a subfield of F_{2^256}, but FAEST's F_{2^256}
    (modulus z^256 + z^10 + z^5 + z^2 + 1) does not contain `a` as z^k.  We
    need gamma in F_{2^256} with gamma^128 + gamma^7 + gamma^2 + gamma + 1 = 0;
    a lane sum_b c_b a^b then maps to sum_b c_b gamma^b.

  * lambda = 192: 128 does not divide 192, so F_{2^128} is not a subfield of
    F_{2^192}.  Their common subfield is F_{2^64}.  We write a lane as
    A + B*a with A, B in the F_{2^64} subfield of F_{2^128}
    (a^2 = c1*a + c0 with c1 = a + a^(2^64), c0 = a^(1+2^64)), and embed
    A, B into F_{2^192} through a fixed F_{2^64}.  F_{2^64} is taken with
    FAEST's own modulus u^64 + u^4 + u^3 + u + 1; we need a root eps of it in
    F_{2^128} and a root eta of it in F_{2^192}.

Everything here is F_2-linear except the root finding, which uses the
standard equal-degree (Cantor-Zassenhaus, trace map) splitting.  The script
checks every table it emits: homomorphism on random products, irreducibility
of the tower polynomial, and that embedded constants agree with the lanes.

Output: ../rain_tower_tables.hpp  (C++ arrays, little-endian bytes)
"""
import os
import random
import sys

random.seed(0x5241494E)  # "RAIN"; only affects search order, not results

# ---------------------------------------------------------------------------
# GF(2)[x] helpers on Python ints (bit i = coefficient of x^i)
# ---------------------------------------------------------------------------

def clmul(a, b):
    r = 0
    while b:
        lsb = b & -b
        r ^= a << (lsb.bit_length() - 1)
        b ^= lsb
    return r


def pmod(a, m):
    dm = m.bit_length() - 1
    while a.bit_length() - 1 >= dm:
        a ^= m << (a.bit_length() - 1 - dm)
    return a


class GF:
    """GF(2^n) = GF(2)[x]/(modulus)."""

    def __init__(self, n, modulus):
        assert modulus.bit_length() - 1 == n
        self.n, self.mod = n, modulus

    def mul(self, a, b):
        return pmod(clmul(a, b), self.mod)

    def sqr(self, a):
        return self.mul(a, a)

    def pow(self, a, e):
        r = 1
        while e:
            if e & 1:
                r = self.mul(r, a)
            a = self.sqr(a)
            e >>= 1
        return r

    def inv(self, a):
        assert a != 0
        return self.pow(a, (1 << self.n) - 2)

    def frob(self, a, k):
        for _ in range(k):
            a = self.sqr(a)
        return a

    def rand(self):
        return random.getrandbits(self.n)


def poly_from_exps(*exps):
    v = 0
    for e in exps:
        v |= 1 << e
    return v


F128 = GF(128, poly_from_exps(128, 7, 2, 1, 0))
F192 = GF(192, poly_from_exps(192, 7, 2, 1, 0))
F256 = GF(256, poly_from_exps(256, 10, 5, 2, 0))
Q64 = poly_from_exps(64, 4, 3, 1, 0)       # FAEST's F_{2^64} modulus
P128 = F128.mod                            # Rain lane modulus (a^128+a^7+a^2+a+1)

# ---------------------------------------------------------------------------
# Polynomials over GF(2^n): lists of ints, index = degree
# ---------------------------------------------------------------------------

def ptrim(p):
    while p and p[-1] == 0:
        p.pop()
    return p


def pdivmod(F, a, b):
    a = list(a)
    b = ptrim(list(b))
    inv_lead = F.inv(b[-1])
    q = [0] * max(1, len(a) - len(b) + 1)
    while len(ptrim(a)) >= len(b):
        shift = len(a) - len(b)
        c = F.mul(a[-1], inv_lead)
        q[shift] = c
        for i, bi in enumerate(b):
            a[i + shift] ^= F.mul(c, bi)
        ptrim(a)
    return q, a


def pgcd(F, a, b):
    a, b = ptrim(list(a)), ptrim(list(b))
    while b:
        _, r = pdivmod(F, a, b)
        a, b = b, r
    inv = F.inv(a[-1])
    return [F.mul(c, inv) for c in a]


def reduce_mod_f2poly(F, p, m_bits):
    """Reduce p (coeffs in GF(2^n)) modulo a monic GF(2)-polynomial m."""
    dm = m_bits.bit_length() - 1
    taps = [i for i in range(dm) if (m_bits >> i) & 1]
    p = list(p)
    for i in range(len(p) - 1, dm - 1, -1):
        c = p[i]
        if c:
            p[i] = 0
            for t in taps:
                p[i - dm + t] ^= c
    return ptrim(p[:dm])


def roots_in_field(F, m_bits):
    """All we need is one root in F of the GF(2)-irreducible m (deg d | n)."""
    dm = m_bits.bit_length() - 1
    assert F.n % dm == 0
    poly = [(m_bits >> i) & 1 for i in range(dm + 1)]
    first = True
    while len(poly) - 1 > 1:
        while True:
            delta = F.rand()
            # T(Y) = sum_{i<n} (delta*Y)^{2^i} mod poly
            cur = [0, delta]
            acc = [0, delta]
            for _ in range(F.n - 1):
                sq = [0] * (2 * len(cur) - 1)
                for i, c in enumerate(cur):
                    sq[2 * i] = F.sqr(c)
                cur = reduce_mod_f2poly(F, sq, m_bits) if first else generic_mod(F, sq, poly)
                acc = padd(acc, cur)
            g = pgcd(F, poly, acc)
            if 0 < len(g) - 1 < len(poly) - 1:
                h, r = pdivmod(F, poly, g)
                assert not ptrim(r)
                poly = g if len(g) <= len(h) else ptrim(h)
                inv = F.inv(poly[-1])
                poly = [F.mul(c, inv) for c in poly]
                first = False
                break
    # poly = Y + c  ->  root = c
    root = poly[0]
    assert eval_f2poly(F, m_bits, root) == 0
    return root


def padd(a, b):
    n = max(len(a), len(b))
    return ptrim([(a[i] if i < len(a) else 0) ^ (b[i] if i < len(b) else 0) for i in range(n)])


def generic_mod(F, p, m):
    _, r = pdivmod(F, p, m)
    return r


def eval_f2poly(F, m_bits, x):
    acc, xp = 0, 1
    for i in range(m_bits.bit_length()):
        if (m_bits >> i) & 1:
            acc ^= xp
        xp = F.mul(xp, x)
    return acc

# ---------------------------------------------------------------------------
# The Rain tower F_{2^128}[X]/(X^4 + a^123 X^2 + X + 1)
# ---------------------------------------------------------------------------

A123 = 1 << 123


def tower_mul(F, mul, x, y, a123):
    """x, y: 4 coefficients; mul: coefficient multiplication; a123: constant."""
    c = [None] * 7
    for i in range(4):
        for j in range(4):
            c[i + j] = add(c[i + j], mul(x[i], y[j]))
    for k in (6, 5, 4):           # X^4 = a^123 X^2 + X + 1
        ck = c[k]
        c[k] = zero_like(ck)
        c[k - 2] = add(c[k - 2], mul(a123, ck))
        c[k - 3] = add(c[k - 3], ck)
        c[k - 4] = add(c[k - 4], ck)
    return c[:4]


def add(a, b):
    if a is None:
        return b
    if isinstance(a, tuple):
        return tuple(x ^ y for x, y in zip(a, b))
    return a ^ b


def zero_like(a):
    return tuple(0 for _ in a) if isinstance(a, tuple) else 0


def check_tower_irreducible():
    # f = X^4 + a^123 X^2 + X + 1 over F_{2^128} has no roots and no
    # quadratic factor iff gcd(f, X^{q^k} - X) = 1 for k = 1, 2 (q = 2^128).
    f = [1, 1, A123, 0, 1]
    xp = [0, 1]
    for k in (1, 2):
        for _ in range(128):
            sq = [0] * (2 * len(xp) - 1)
            for i, c in enumerate(xp):
                sq[2 * i] = F128.sqr(c)
            xp = generic_mod(F128, sq, f)
        g = pgcd(F128, f, padd(xp, [0, 1]))
        assert len(g) == 1, f"tower polynomial has a degree-{k} factor"
    return True

# ---------------------------------------------------------------------------
# Level 5: lanes into F_{2^256}
# ---------------------------------------------------------------------------

def derive_l5():
    gamma = roots_in_field(F256, P128)
    table = [F256.pow(gamma, b) for b in range(128)]

    def emb(lane):
        v = 0
        for b in range(128):
            if (lane >> b) & 1:
                v ^= table[b]
        return v

    for _ in range(200):  # ring homomorphism on F_{2^128}
        x, y = F128.rand(), F128.rand()
        assert emb(F128.mul(x, y)) == F256.mul(emb(x), emb(y))
    for _ in range(50):   # whole tower product
        x = [F128.rand() for _ in range(4)]
        y = [F128.rand() for _ in range(4)]
        lhs = [emb(c) for c in tower_mul(F128, F128.mul, x, y, A123)]
        rhs = tower_mul(F256, F256.mul, [emb(c) for c in x], [emb(c) for c in y], emb(A123))
        assert lhs == rhs
    return table

# ---------------------------------------------------------------------------
# Level 3: lanes into F_{2^64}^2 inside F_{2^192}
# ---------------------------------------------------------------------------

def solve_f2(cols, target, nbits):
    """Express `target` as XOR of a subset of `cols` (all ints); returns mask."""
    basis = []  # (vector, combination mask)
    for i, c in enumerate(cols):
        v, m = c, 1 << i
        for bv, bm in basis:
            if v ^ bv < v:
                v, m = v ^ bv, m ^ bm
        if v:
            basis.append((v, m))
            basis.sort(key=lambda t: -t[0])
    v, m = target, 0
    for bv, bm in basis:
        if v ^ bv < v:
            v, m = v ^ bv, m ^ bm
    assert v == 0, "not in span"
    return m


def derive_l3():
    eps = roots_in_field(F128, Q64)        # F_{2^64} inside F_{2^128}
    eta = roots_in_field(F192, Q64)        # F_{2^64} inside F_{2^192}
    eps_pows = [F128.pow(eps, j) for j in range(64)]
    eta_pows = [F192.pow(eta, j) for j in range(64)]

    def iota(sub):  # element of the F_{2^64} subfield of F_{2^128} -> F_{2^192}
        assert F128.frob(sub, 64) == sub, "not in the F_{2^64} subfield"
        m = solve_f2(eps_pows, sub, 128)
        v = 0
        for j in range(64):
            if (m >> j) & 1:
                v ^= eta_pows[j]
        return v

    a = 2                                   # the lane generator `a`
    a_conj = F128.frob(a, 64)
    c1 = a ^ a_conj
    c0 = F128.mul(a, a_conj)
    assert F128.sqr(a) == F128.mul(c1, a) ^ c0
    denom_inv = F128.inv(a ^ a_conj)

    def split(x):  # x = A + B*a with A, B in F_{2^64}
        B = F128.mul(x ^ F128.frob(x, 64), denom_inv)
        A = x ^ F128.mul(B, a)
        return A, B

    tabA, tabB = [], []
    for b in range(128):
        A, B = split(1 << b)
        tabA.append(iota(A))
        tabB.append(iota(B))

    def emb(lane):
        A = B = 0
        for b in range(128):
            if (lane >> b) & 1:
                A ^= tabA[b]
                B ^= tabB[b]
        return (A, B)

    c0e, c1e = iota(c0), iota(c1)

    def pmul(x, y):  # (A1 + B1 a)(A2 + B2 a), a^2 = c1 a + c0
        A1, B1 = x
        A2, B2 = y
        bb = F192.mul(B1, B2)
        return (F192.mul(A1, A2) ^ F192.mul(bb, c0e),
                F192.mul(A1, B2) ^ F192.mul(A2, B1) ^ F192.mul(bb, c1e))

    for _ in range(200):
        x, y = F128.rand(), F128.rand()
        assert emb(F128.mul(x, y)) == pmul(emb(x), emb(y))
    for _ in range(30):
        x = [F128.rand() for _ in range(4)]
        y = [F128.rand() for _ in range(4)]
        lhs = [emb(c) for c in tower_mul(F128, F128.mul, x, y, A123)]
        rhs = tower_mul(None, pmul, [emb(c) for c in x], [emb(c) for c in y], emb(A123))
        assert lhs == rhs
    return tabA, tabB, c0e, c1e

# ---------------------------------------------------------------------------

def to_bytes(v, nbytes):
    return v.to_bytes(nbytes, "little")


def c_array(name, rows, nbytes):
    out = [f"alignas(32) inline constexpr unsigned char {name}[{len(rows)}][{nbytes}] = {{"]
    for r in rows:
        out.append("    {" + ", ".join(f"0x{b:02x}" for b in to_bytes(r, nbytes)) + "},")
    out.append("};")
    return "\n".join(out)


def c_vec(name, v, nbytes):
    return (f"alignas(32) inline constexpr unsigned char {name}[{nbytes}] = {{"
            + ", ".join(f"0x{b:02x}" for b in to_bytes(v, nbytes)) + "};")


def main():
    check_tower_irreducible()
    print("tower polynomial X^4 + a^123 X^2 + X + 1 is irreducible over F_2^128", file=sys.stderr)
    t256 = derive_l5()
    print("level 5 lane embedding verified", file=sys.stderr)
    tA, tB, c0, c1 = derive_l3()
    print("level 3 lane embedding verified", file=sys.stderr)

    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "rain_tower_tables.hpp")
    with open(path, "w") as f:
        f.write("// Generated by tools/derive_rain_tower.py -- do not edit by hand.\n")
        f.write("//\n// Lane embeddings for the RainHash-512 S-box check at NIST levels 3 and 5.\n")
        f.write("// A 128-bit Rain lane sum_b c_b a^b (a^128 = a^7 + a^2 + a + 1) maps to\n")
        f.write("//   level 5: sum_b c_b RAIN_LANE_EMB_256[b]          in F_{2^256}\n")
        f.write("//   level 3: (sum_b c_b RAIN_LANE_EMB_192_A[b],\n")
        f.write("//             sum_b c_b RAIN_LANE_EMB_192_B[b])    in F_{2^192}^2,\n")
        f.write("//            representing A + B*a with a^2 = C1*a + C0.\n")
        f.write("// Both maps are ring homomorphisms (checked by the generator).\n\n")
        f.write("#ifndef RAIN_TOWER_TABLES_HPP\n#define RAIN_TOWER_TABLES_HPP\n\n")
        f.write("namespace faest {\n\n")
        f.write(c_array("RAIN_LANE_EMB_256", t256, 32) + "\n\n")
        f.write(c_array("RAIN_LANE_EMB_192_A", tA, 24) + "\n\n")
        f.write(c_array("RAIN_LANE_EMB_192_B", tB, 24) + "\n\n")
        f.write(c_vec("RAIN_LANE_192_C0", c0, 24) + "\n")
        f.write(c_vec("RAIN_LANE_192_C1", c1, 24) + "\n\n")
        f.write("} // namespace faest\n\n#endif\n")
    print(f"wrote {os.path.normpath(path)}", file=sys.stderr)


if __name__ == "__main__":
    main()
