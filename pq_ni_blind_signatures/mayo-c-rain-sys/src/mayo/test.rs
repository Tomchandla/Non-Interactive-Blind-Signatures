//! This was only a module used for testing, but it can still be used for simple map
//! evaluations.
//! It was created to mimic the behavior of the evaluation that is performed within the
//! circuit and designed for debugging purposes.
//! After additional modification, the circuit is not following this plain implementation
//! anymore, but this native version might still be of interest.

use crate::mayo::{
    MAYOParameters,
    key_expansion::{pack_u4_to_u8, unpack_u4_from_u8},
};

/// Together this function allowed to evaluate the map using rust code.
/// It is a rebuild of an older version of the circuit, but it can still be
/// used to compute the map evaluation of MAYO.
/// The input needs to be from [`MAYO::expand_pk_p1_p2_p3_reordered`](crate::mayo::MAYO::expand_pk_p1_p2_p3_reordered).
#[allow(dead_code)]
pub(crate) fn evaluate_map(
    p: &MAYOParameters,
    p1: &[u8],
    p2: &[u8],
    p3: &[u8],
    sig: &[u8],
    f_tails: &[u8; 4],
) -> Vec<u8> {
    let k = p.mayo_param_set.k as usize;

    let m = p.m;
    let n = p.o + p.v;
    let v = p.v;
    let o = p.o;
    let p1a_elem_size = v * v;
    let p2a_elem_size = v * o;
    let p3a_elem_size = o * o;

    let mut ep1: Vec<u8> = p1.to_vec();
    let mut ep2: Vec<u8> = p2.to_vec();
    let mut ep3: Vec<u8> = p3.to_vec();

    let su8 = unpack_u4_from_u8(sig, p.sig_bytes * 2);

    let mut uu8 = vec![0; m];

    let mut l = 0;

    for i in 0..k {
        for j in (i..k).rev() {
            if l != 0 {
                ep1 = apply_e_p(&ep1, p1a_elem_size, p, f_tails);
                ep2 = apply_e_p(&ep2, p2a_elem_size, p, f_tails);
                ep3 = apply_e_p(&ep3, p3a_elem_size, p, f_tails);
            }
            l += 1;

            let epa1u8 = unpack_u4_from_u8(&ep1, p1a_elem_size * m);
            let epa2u8 = unpack_u4_from_u8(&ep2, p2a_elem_size * m);
            let epa3u8 = unpack_u4_from_u8(&ep3, p3a_elem_size * m);

            let mut spu8_i = vec![0; n];
            let mut spu8_j = vec![0; n];

            for a in 0..m {
                // Reading the columns in major
                for col in 0..n {
                    spu8_i[col] = 0;
                    spu8_j[col] = 0;
                    for row in 0..n {
                        if row < (n - o) && col < (n - o) {
                            spu8_i[col] ^= mul_mod(
                                su8[i * n + row],
                                epa1u8[a * (p1a_elem_size) + col * (n - o) + row],
                            );
                            if i != j {
                                spu8_j[col] ^= mul_mod(
                                    su8[j * n + row],
                                    epa1u8[a * (p1a_elem_size) + col * (n - o) + row],
                                );
                            }
                        } else if row < n - o && col >= n - o {
                            spu8_i[col] ^= mul_mod(
                                su8[i * n + row],
                                epa2u8[a * p2a_elem_size + (col - (n - o)) * (n - o) + row],
                            );
                            if i != j {
                                spu8_j[col] ^= mul_mod(
                                    su8[j * n + row],
                                    epa2u8[a * p2a_elem_size + (col - (n - o)) * (n - o) + row],
                                );
                            }
                        } else if row >= n - o && col >= n - o {
                            spu8_i[col] ^= mul_mod(
                                su8[i * n + row],
                                epa3u8[a * p3a_elem_size + (col - (n - o)) * o + (row - (n - o))],
                            );
                            if i != j {
                                spu8_j[col] ^= mul_mod(
                                    su8[j * n + row],
                                    epa3u8
                                        [a * p3a_elem_size + (col - (n - o)) * o + (row - (n - o))],
                                );
                            }
                        }
                    }
                }
                for idx in 0..n {
                    if i == j {
                        // s_i P s_i
                        uu8[a] ^= mul_mod(spu8_i[idx], su8[i * n + idx]);
                    } else {
                        // s_i P s_j
                        uu8[a] ^= mul_mod(spu8_i[idx], su8[j * n + idx]);
                        // s_j P s_i
                        uu8[a] ^= mul_mod(spu8_j[idx], su8[i * n + idx]);
                    }
                }
            }
        }
    }

    pack_u4_to_u8(&uu8)
}

/// reducing with the reduction poly in F_2^4
#[allow(dead_code)]
fn mod_reduce(a: u8) -> u8 {
    let mut c = a;
    for i in (4..8).rev() {
        if (c >> i) % 2 == 1 {
            c ^= VOLEMAYO_MOD << (i - 4);
        }
    }
    c
}

pub const VOLEMAYO_MOD: u8 = 19;

/// carry less mult
#[allow(dead_code)]
fn mul_mod(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut c = 0;
    while b != 0 {
        if b % 2 == 1 {
            c ^= a;
        }
        a <<= 1;
        b >>= 1;
    }

    mod_reduce(c)
}

/// multiplication with the matrix E
#[allow(dead_code)]
fn apply_e_p(
    epabytes: &[u8],
    elem_per_matrix: usize,
    p: &MAYOParameters,
    f_tails: &[u8; 4],
) -> Vec<u8> {
    let m = p.m;
    let unpacked = unpack_u4_from_u8(epabytes, m * elem_per_matrix);

    let pm = unpacked[(m - 1) * elem_per_matrix..].to_vec();

    let mut pm_f0 = vec![0; elem_per_matrix];
    let mut pm_f1 = vec![0; elem_per_matrix];
    let mut pm_f2 = vec![0; elem_per_matrix];
    let mut pm_f3 = vec![0; elem_per_matrix];

    for i in 0..elem_per_matrix {
        pm_f0[i] = mul_mod(pm[i], f_tails[0]);
        pm_f1[i] = mul_mod(pm[i], f_tails[1]);
        pm_f2[i] = mul_mod(pm[i], f_tails[2]);
        pm_f3[i] = mul_mod(pm[i], f_tails[3]);
    }

    let mut tmp_eepa = vec![0; unpacked.len()];
    for i in 0..elem_per_matrix {
        tmp_eepa[i] = pm_f0[i];
        tmp_eepa[elem_per_matrix + i] = pm_f1[i] ^ unpacked[i];
        tmp_eepa[2 * elem_per_matrix + i] = pm_f2[i] ^ unpacked[elem_per_matrix + i];
        tmp_eepa[3 * elem_per_matrix + i] = pm_f3[i] ^ unpacked[2 * elem_per_matrix + i];
        for offset in 4..m {
            tmp_eepa[offset * elem_per_matrix + i] = unpacked[(offset - 1) * elem_per_matrix + i];
        }
    }

    pack_u4_to_u8(&tmp_eepa)
}
