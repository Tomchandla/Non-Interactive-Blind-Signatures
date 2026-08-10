//! This module contains two public key expansion functions.
//!
//! The first one [`MAYO::expand_pk`] calls the expand function from MAYO-C
//! and returns the same format.
//!
//! The second one [`MAYO::expand_pk_p1_p2_p3_reordered`] was primarily for internal
//! debugging purposes, but it can be used for map evaluations and a more intuitive
//! access to the matrices.

use crate::mayo::{MAYO, MAYOEPkType, MAYOPkType};
use crate::{MAYO_OK, P1_LIMBS_MAX, P2_LIMBS_MAX, P3_LIMBS_MAX, mayo_expand_pk};

impl MAYO {
    /// Expands the MAYO pk using MAYOs expanded pk function.
    /// The output format (from MAYO-C) is as follows:
    /// - the matrices P1, P2, P3 are stored sequentually (all P1, then all P2, then all P3)
    /// - the m P1/2/3 matrices are stored interleaved, i.e.: first the first
    ///   entry of every matrix. Then the second of every matrix , etc.
    /// - each m-long vector is padded such that it fills a multiple of u64 entries
    /// - for P1 and P2, only the entries of the upper triangular matrix are stored
    /// - the entries of the matrices are stored in row-major order
    ///
    /// The only modification compared to MAYO-C, is given by the recasting of u64 values
    /// to u8 values.
    ///
    /// # Parameter
    /// - `pk`: The compressed MAYO pk
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::MAYO;
    /// use mayo_c_sys::mayo::MAYOParameterSet;
    ///
    /// let mayo = MAYO::setup(MAYOParameterSet::MAYO5);
    /// let (pk, sk) = mayo.keygen();
    /// let epk = mayo.expand_pk(&pk);
    /// ```
    pub fn expand_pk(&self, pk: &MAYOPkType) -> MAYOEPkType {
        let mp = &self.mayo_params;
        let n = mp.o + mp.v;

        // m/16 yields the number of u64 elements per m vector, and there are n*(n+1)/2 m vectors
        let mut epk_u64 = vec![0u64; (n * (n + 1) / 2) * (mp.mayo_param_set.m_vec_limbs as usize)];
        assert_eq!(MAYO_OK, unsafe {
            mayo_expand_pk(&mp.mayo_param_set, pk.as_ptr(), epk_u64.as_mut_ptr()) as u32
        });

        // cast u64 into byte string
        let byte_ptr = epk_u64.as_mut_ptr().cast::<u8>();
        let byte_slice = unsafe { std::slice::from_raw_parts(byte_ptr, epk_u64.len() * 8) };

        byte_slice.to_vec()
    }

    /// Expands the MAYO public key using the `mayo_expand_pk` function from MAYO-C.
    /// The returned matrices are the P1, P2 and P3 matrices.
    /// However, they are modified in the following ways:
    ///
    /// 0. The `mayo_expand_pk` function returns the individual P1, P2, P3 matrices in an
    ///    interleaved form, i.e. P1_1[0,0], P1_2[0,0], ..., P1_m[0,0], P1_1[0,1], ...
    ///    Each vector of m interleaved elements occupies a u64 vector of size m_vec_limbs
    ///    However, the output is needed in a non-interleaved form.
    /// 1. The `mayo_expand_pk` function returns only the upper triangular matrices for
    ///    P1 and P3, so they are extended to full matrices.
    /// 2. The `mayo_expand_pk` function returns a [u64] array where each entry consists
    ///    of 16 u4 elements. Instead, we wrap the elements in an [u8] array, where the
    ///    even elements are always on the lsb of each [u8]. For the transformation from
    ///    u64 to u8, we first cast the pointer, and then read the two u4 elements
    ///    from LSB to MSB
    /// 3. The `mayo_expand_pk` function returns the elements in row-major order.
    ///    The output is needed to be in column-major order, so a transform is applied at
    ///    the end.
    ///
    /// # Parameter
    /// - `pk`: The compressed MAYO pk
    ///
    /// # Example
    /// ```
    /// // the function is only crate-intern, so the test cant compile
    /// use mayo_c_sys::mayo::MAYO;
    /// use mayo_c_sys::mayo::MAYOParameterSet;
    ///
    /// let mayo = MAYO::setup(MAYOParameterSet::MAYO5);
    /// let (pk, sk) = mayo.keygen();
    /// let (p1, p2, p3) = mayo.expand_pk_p1_p2_p3_reordered(&pk);
    /// ```
    pub fn expand_pk_p1_p2_p3_reordered(&self, pk: &MAYOPkType) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mp = &self.mayo_params;
        let (p1_size, p2_size, p3_size): (usize, usize, usize) = (
            P1_LIMBS_MAX.try_into().unwrap(),
            P2_LIMBS_MAX.try_into().unwrap(),
            P3_LIMBS_MAX.try_into().unwrap(),
        );
        let o = mp.o;
        let n = mp.o + mp.v;
        let m = mp.m;
        let m_vec_limbs = mp.m_vec_limbs;
        let v = n - o;
        let mut expanded_pk = vec![0u64; p1_size + p2_size + p3_size];
        assert_eq!(MAYO_OK, unsafe {
            mayo_expand_pk(&mp.mayo_param_set, pk.as_ptr(), expanded_pk.as_mut_ptr()) as u32
        });

        // cast u64 into byte string
        let byte_ptr = expanded_pk.as_mut_ptr().cast::<u8>();
        let byte_slice = unsafe { std::slice::from_raw_parts(byte_ptr, expanded_pk.len() * 16) };

        // unpack lower and higher bits in each u8
        let unpacked = unpack_u4_from_u8(byte_slice, byte_slice.len() * 2);
        let p1_limbs = v * (v + 1) / 2 * m_vec_limbs * 16;
        let p2_limbs = o * v * m_vec_limbs * 16;
        let p3_limbs = o * (o + 1) / 2 * m_vec_limbs * 16;
        let unpacked_p1 = &unpacked[0..p1_limbs];
        let unpacked_p2 = &unpacked[p1_limbs..p1_limbs + p2_limbs];
        let unpacked_p3 = &unpacked[(p1_limbs + p2_limbs)..(p1_limbs + p2_limbs + p3_limbs)];

        // the public key is stored as follows:
        // it is stored as P1 || P2 || P3
        // each P1, P2, P3 contain m matrices that are stored interleaved
        // each m long vector is assigned a m_vec_limbs long u64 vector
        // the entries themselves are stored in row-major order
        // the entries underneath the diagonal are not included in the expanded public key
        // P1 is from [0..(v*(v+1)/2)*m_vec_limbs] as u64
        // P2 is from there and has o*v*m_vec_limbs u64 elements
        // P3 is from there and has o*(o+1)/2*m_vec_limbs u64 elements

        // the new order must be in column-major:

        let mut p1 = vec![0_u8; v * v * m];
        let mut p2 = vec![0_u8; o * v * m];
        let mut p3 = vec![0_u8; o * o * m];
        // iterate over all m matrices
        for i in 0..m {
            // Iterate over P1 in column_major
            for column in 0..v {
                for row in 0..=column {
                    let entry_pos = (v * (v + 1) / 2 - (v - row) * (v - row + 1) / 2 + column
                        - row)
                        * m_vec_limbs
                        * 16
                        + i;
                    // all entries - all non-completed rows + entries in current row
                    // the multiplication with m_vec_limbs due to the interleaved storage
                    // the multiplication with 16, because we go from u64 to u4
                    p1[i * v * v + column * v + row] = unpacked_p1[entry_pos];
                }
            }

            // Iterate over P2 in column_major
            for column in 0..o {
                for row in 0..v {
                    let entry_pos = (row * o + column) * m_vec_limbs * 16 + i;
                    p2[i * o * v + column * v + row] = unpacked_p2[entry_pos];
                }
            }

            // Iterate over P3 in column_major
            for column in 0..o {
                for row in 0..=column {
                    let entry_pos = (o * (o + 1) / 2 - (o - row) * (o - row + 1) / 2 + column
                        - row)
                        * m_vec_limbs
                        * 16
                        + i;
                    p3[i * o * o + column * o + row] = unpacked_p3[entry_pos];
                }
            }
        }

        (pack_u4_to_u8(&p1), pack_u4_to_u8(&p2), pack_u4_to_u8(&p3))
    }
}

/// Unpack a slice of u4 values (2 stored per u8) into a Vec<u8> of u4 elements.
/// The uneven elements are in the msb of the u8 and the even bits are in the lsb
pub(crate) fn unpack_u4_from_u8(data: &[u8], total_u4s: usize) -> Vec<u8> {
    let mut unpacked = Vec::with_capacity(total_u4s);
    for &byte in data {
        if unpacked.len() == total_u4s {
            break;
        }
        // Low 4 bits
        unpacked.push(byte & 0xF);
        if unpacked.len() == total_u4s {
            break;
        }
        // High 4 bits
        unpacked.push((byte >> 4) & 0xF);
    }
    unpacked
}

/// Pack a slice of u4 values (stored as u8) into a Vec<u8>, 2 u4 packed per u8.
/// The uneven elements are in the msb of the u8 and the even bits are in the lsb
pub(crate) fn pack_u4_to_u8(u4_values: &[u8]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(u4_values.len().div_ceil(2));
    let mut i = 0;
    while i < u4_values.len() {
        let low = u4_values[i] & 0xF;
        let high = if i + 1 < u4_values.len() {
            (u4_values[i + 1] & 0xF) << 4
        } else {
            0
        };
        packed.push(low | high);
        i += 2;
    }
    packed
}
