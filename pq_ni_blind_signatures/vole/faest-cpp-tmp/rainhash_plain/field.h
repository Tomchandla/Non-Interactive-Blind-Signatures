// NOTE: This is the same field implementation stuff from the rainhash_plain implementation in the main directory


#ifndef FIELD_H
#define FIELD_H

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>
extern "C" {
#include <emmintrin.h>
#include <immintrin.h>
}



namespace {

// 128 field
inline void clmul_karatsuba_128(__m128i out[2], const __m128i a, const __m128i b) {
  __m128i tmp[4];
  out[0] = _mm_clmulepi64_si128(a, b, 0x00);
  out[1] = _mm_clmulepi64_si128(a, b, 0x11);

  tmp[0] = _mm_srli_si128(a, 8);
  tmp[1] = _mm_xor_si128(a, tmp[0]);
  tmp[2] = _mm_srli_si128(b, 8);
  tmp[3] = _mm_xor_si128(b, tmp[2]);

  tmp[0] = _mm_clmulepi64_si128(tmp[1], tmp[3], 0x00);
  tmp[1] = _mm_xor_si128(out[1], out[0]);
  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);

  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[0] = _mm_xor_si128(out[0], tmp[1]);
  out[1] = _mm_xor_si128(out[1], tmp[2]);
}
inline void reduce_clmul_128(__m128i out[1], const __m128i in[2]) {
  __m128i p = _mm_set_epi64x(0x0, 0x87);
  __m128i t0, t1, t2;
  t0 = _mm_clmulepi64_si128(in[1], p, 0x01); // in[1]_high * p
  t1 = _mm_slli_si128(t0, 8);    // low 64bit of result, shifted to high
  t2 = _mm_srli_si128(t0, 8);    // high 64bit of result, shifted to high
  t2 = _mm_xor_si128(t2, in[1]); // update in[1]_low with high64 of result

  t0 = _mm_clmulepi64_si128(t2, p, 0x00); // updated in[1]_low * p
  out[0] = _mm_xor_si128(t0, in[0]);      // add in[1]_low * p to result
  out[0] = _mm_xor_si128(out[0], t1); // also add the low part of in[1]_high * p
}
inline void mul_gf128(__m128i out[1], const __m128i a, const __m128i b) {
  __m128i mult[2];
  clmul_karatsuba_128(mult, a, b);
  reduce_clmul_128(&out[0], mult);

}
inline __m128i mul_gf128_ret(const __m128i a, const __m128i b) {
  __m128i out;
  __m128i mult[2];
  clmul_karatsuba_128(mult, a, b);
  reduce_clmul_128(&out, mult);
  return out;
}
inline void deg3_reduce(__m128i prod[7]) {

  // x^4 + a^123 * x^2 + x + 1
  __m128i poly_irr[5];
  poly_irr[0] = _mm_set_epi64x(0x00, 0x01);
  poly_irr[1] = _mm_set_epi64x(0x00, 0x01);
  poly_irr[2] = _mm_set_epi64x((uint64_t)0x01 << 59, 0x00); // setting the 124th bit
  poly_irr[3] = _mm_set_epi64x(0x00, 0x00);
  poly_irr[4] = _mm_set_epi64x(0x00, 0x01);

  __m128i redu_term[5];

  // Reducing deg-6
  // Getting the reducing term
  mul_gf128(&redu_term[4], prod[6], poly_irr[4]);
  mul_gf128(&redu_term[3], prod[6], poly_irr[3]);
  mul_gf128(&redu_term[2], prod[6], poly_irr[2]);
  mul_gf128(&redu_term[1], prod[6], poly_irr[1]);
  mul_gf128(&redu_term[0], prod[6], poly_irr[0]);
  // Doing the reduction substraction
  prod[6] = _mm_xor_si128(prod[6], redu_term[4]);
  prod[5] = _mm_xor_si128(prod[5], redu_term[3]);
  prod[4] = _mm_xor_si128(prod[4], redu_term[2]);
  prod[3] = _mm_xor_si128(prod[3], redu_term[1]);
  prod[2] = _mm_xor_si128(prod[2], redu_term[0]);

  // Reducing deg-5
  // Getting the reducing term
  mul_gf128(&redu_term[4], prod[5], poly_irr[4]);
  mul_gf128(&redu_term[3], prod[5], poly_irr[3]);
  mul_gf128(&redu_term[2], prod[5], poly_irr[2]);
  mul_gf128(&redu_term[1], prod[5], poly_irr[1]);
  mul_gf128(&redu_term[0], prod[5], poly_irr[0]);
  // Doing the reduction substraction
  prod[5] = _mm_xor_si128(prod[5], redu_term[4]);
  prod[4] = _mm_xor_si128(prod[4], redu_term[3]);
  prod[3] = _mm_xor_si128(prod[3], redu_term[2]);
  prod[2] = _mm_xor_si128(prod[2], redu_term[1]);
  prod[1] = _mm_xor_si128(prod[1], redu_term[0]);

  // Reducing deg-4
  // Getting the reducing term
  mul_gf128(&redu_term[4], prod[4], poly_irr[4]);
  mul_gf128(&redu_term[3], prod[4], poly_irr[3]);
  mul_gf128(&redu_term[2], prod[4], poly_irr[2]);
  mul_gf128(&redu_term[1], prod[4], poly_irr[1]);
  mul_gf128(&redu_term[0], prod[4], poly_irr[0]);
  // Doing the reduction substraction
  prod[4] = _mm_xor_si128(prod[4], redu_term[4]);
  prod[3] = _mm_xor_si128(prod[3], redu_term[3]);
  prod[2] = _mm_xor_si128(prod[2], redu_term[2]);
  prod[1] = _mm_xor_si128(prod[1], redu_term[1]);
  prod[0] = _mm_xor_si128(prod[0], redu_term[0]);

}
inline void deg3_clmul(__m128i c[7], const __m128i a[4], const __m128i b[4]) {


  __m128i poly_deg2 = _mm_set_epi64x(((uint64_t)0x01 << 59), 0x00); // setting the 124th bit

  /*
  c0 = a0*b0
  c1 = a0*b1 + a1*b0
  c2 = a0*b2 + a1*b1 + a2*b0
  c3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
  c4 = a1*b3 + a2*b2 + a3*b1
  c5 = a2*b3 + a3*b2
  c6 = a3*b3

  d0 = c0 + c4 + a^123 * c6
  d1 = c1 + c4 + c5 + a^123 * c6
  d2 = c2 + a^123 * c4 + c5 + ( 1 + a^246 ) * c6
  d3 = c3 + a^123 * c5 + c6
  */
  
  c[0] = mul_gf128_ret(a[0], b[0]) 
        ^ mul_gf128_ret(a[3], b[1]) ^ mul_gf128_ret(a[1], b[3]) ^ mul_gf128_ret(a[2], b[2]) 
        ^ mul_gf128_ret(mul_gf128_ret(a[3], b[3]), poly_deg2);
  
  c[1] = mul_gf128_ret(a[1], b[0]) ^ mul_gf128_ret(a[0], b[1]) 
      ^ mul_gf128_ret(a[3], b[1]) ^ mul_gf128_ret(a[1], b[3]) ^ mul_gf128_ret(a[2], b[2])
      ^ mul_gf128_ret(a[3], b[2]) ^ mul_gf128_ret(a[2], b[3]) 
      ^ mul_gf128_ret(mul_gf128_ret(a[3], b[3]), poly_deg2);

  c[2] = mul_gf128_ret(a[2], b[0]) ^ mul_gf128_ret(a[0], b[2]) ^ mul_gf128_ret(a[1], b[1]) 
      ^ mul_gf128_ret(mul_gf128_ret(a[3], b[1]) ^ mul_gf128_ret(a[1], b[3]) ^ mul_gf128_ret(a[2], b[2]), poly_deg2)
      ^ mul_gf128_ret(a[3], b[2]) ^ mul_gf128_ret(a[2], b[3]) 
      ^ mul_gf128_ret(a[3], b[3]) ^ mul_gf128_ret(mul_gf128_ret(mul_gf128_ret(a[3], b[3]), poly_deg2), poly_deg2);

  c[3] = mul_gf128_ret(a[3], b[0]) ^ mul_gf128_ret(a[0], b[3]) ^ mul_gf128_ret(a[2], b[1]) ^ mul_gf128_ret(a[1], b[2]) 
      ^ mul_gf128_ret(mul_gf128_ret(a[3], b[2]) ^ mul_gf128_ret(a[2], b[3]), poly_deg2)
      ^ mul_gf128_ret(a[3], b[3]);
      
  /*
  // a_3b_3 x^6
  __m128i out[2];
  clmul_karatsuba_128(out, a[3], b[3]);
  reduce_clmul_128(&c[6], out);

  // (a_3b_2+a_2 b_3 )x^5
  clmul_karatsuba_128(out, a[3], b[2]);
  reduce_clmul_128(&c[5], out);
  __m128i tmp;
  clmul_karatsuba_128(out, a[2], b[3]);
  reduce_clmul_128(&tmp, out);
  c[5] += tmp;

  // (a_3b_1+a_1b_3+a_2b_2)x^4
  clmul_karatsuba_128(out, a[3], b[1]);
  reduce_clmul_128(&c[4], out);
  clmul_karatsuba_128(out, a[1], b[3]);
  reduce_clmul_128(&tmp, out);
  c[4] += tmp;
  clmul_karatsuba_128(out, a[2], b[2]);
  reduce_clmul_128(&tmp, out);
  c[4] += tmp;

  // (a_3b_0+a_0b_3+a_2b_1+a_1b_2)x^3
  clmul_karatsuba_128(out, a[3], b[0]);
  reduce_clmul_128(&c[3], out);
  clmul_karatsuba_128(out, a[0], b[3]);
  reduce_clmul_128(&tmp, out);
  c[3] += tmp;
  clmul_karatsuba_128(out, a[2], b[1]);
  reduce_clmul_128(&tmp, out);
  c[3] += tmp;
  clmul_karatsuba_128(out, a[1], b[2]);
  reduce_clmul_128(&tmp, out);
  c[3] += tmp;

  // (a_2b_0+a_0b_2+a_1b_1)x^2
  clmul_karatsuba_128(out, a[2], b[0]);
  reduce_clmul_128(&c[2], out);
  clmul_karatsuba_128(out, a[0], b[2]);
  reduce_clmul_128(&tmp, out);
  c[2] += tmp;
  clmul_karatsuba_128(out, a[1], b[1]);
  reduce_clmul_128(&tmp, out);
  c[2] += tmp;
  
  // (a_1b_0+a_0b_1)x
  clmul_karatsuba_128(out, a[1], b[0]);
  reduce_clmul_128(&c[1], out);
  clmul_karatsuba_128(out, a[0], b[1]);
  reduce_clmul_128(&tmp, out);
  c[1] += tmp;

  // a_0b_0
  clmul_karatsuba_128(out, a[0], b[0]);
  reduce_clmul_128(&c[0], out);

  */

}

// 256 field
inline void clmul_schoolbook_256(__m128i out[4], const __m128i a[2], const __m128i b[2]) {
  __m128i tmp[4];
  
  out[0] = _mm_clmulepi64_si128(a[0], b[0], 0x00);
  out[1] = _mm_clmulepi64_si128(a[0], b[0], 0x11);
  out[1] = _mm_xor_si128(out[1], _mm_clmulepi64_si128(a[0], b[1], 0x00));
  out[1] = _mm_xor_si128(out[1], _mm_clmulepi64_si128(a[1], b[0], 0x00));

  out[2] = _mm_clmulepi64_si128(a[1], b[1], 0x00);
  out[3] = _mm_clmulepi64_si128(a[1], b[1], 0x11);
  out[2] = _mm_xor_si128(out[2], _mm_clmulepi64_si128(a[0], b[1], 0x11));
  out[2] = _mm_xor_si128(out[2], _mm_clmulepi64_si128(a[1], b[0], 0x11));

  
  tmp[0] = _mm_clmulepi64_si128(a[0], b[0], 0x01);
  tmp[1] = _mm_clmulepi64_si128(a[0], b[0], 0x10);

  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[0] = _mm_xor_si128(out[0], tmp[1]);
  out[1] = _mm_xor_si128(out[1], tmp[2]);

  tmp[0] = _mm_clmulepi64_si128(a[1], b[0], 0x10);
  tmp[1] = _mm_clmulepi64_si128(a[0], b[1], 0x01);
  tmp[2] = _mm_clmulepi64_si128(a[0], b[1], 0x10);
  tmp[3] = _mm_clmulepi64_si128(a[1], b[0], 0x01);

  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[2] = _mm_xor_si128(tmp[2], tmp[3]);
  tmp[0] = _mm_xor_si128(tmp[0], tmp[2]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[1] = _mm_xor_si128(out[1], tmp[1]);
  out[2] = _mm_xor_si128(out[2], tmp[2]);

  tmp[0] = _mm_clmulepi64_si128(a[1], b[1], 0x01);
  tmp[1] = _mm_clmulepi64_si128(a[1], b[1], 0x10);

  tmp[0] = _mm_xor_si128(tmp[0], tmp[1]);
  tmp[1] = _mm_slli_si128(tmp[0], 8);
  tmp[2] = _mm_srli_si128(tmp[0], 8);

  out[2] = _mm_xor_si128(out[2], tmp[1]);
  out[3] = _mm_xor_si128(out[3], tmp[2]);

}
inline void sqr_256(__m128i out[4], const __m128i a[2]) {
  __m128i tmp[2];
  __m128i sqrT = _mm_set_epi64x(0x5554515045444140, 0x1514111005040100);
  __m128i mask = _mm_set_epi64x(0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F);
  tmp[0] = _mm_and_si128(a[0], mask);
  tmp[1] = _mm_srli_epi64(a[0], 4);
  tmp[1] = _mm_and_si128(tmp[1], mask);
  tmp[0] = _mm_shuffle_epi8(sqrT, tmp[0]);
  tmp[1] = _mm_shuffle_epi8(sqrT, tmp[1]);
  out[0] = _mm_unpacklo_epi8(tmp[0], tmp[1]);
  out[1] = _mm_unpackhi_epi8(tmp[0], tmp[1]);

  tmp[0] = _mm_and_si128(a[1], mask);
  tmp[1] = _mm_srli_epi64(a[1], 4);
  tmp[1] = _mm_and_si128(tmp[1], mask);
  tmp[0] = _mm_shuffle_epi8(sqrT, tmp[0]);
  tmp[1] = _mm_shuffle_epi8(sqrT, tmp[1]);
  out[2] = _mm_unpacklo_epi8(tmp[0], tmp[1]);
  out[3] = _mm_unpackhi_epi8(tmp[0], tmp[1]);
}
inline void reduce_clmul_256(__m128i out[2], __m128i in[4]) {

  // modulus = x^256 + x^10 + x^5 + x^2 + 1
  uint64_t nums[2];

  __m128i p = _mm_set_epi64x(0, 0x425);
  __m128i t0, t1, t2, out_t1, out_t2;

  t0 = _mm_clmulepi64_si128(in[3], p, 0x01);
  t1 = _mm_slli_si128(t0, 8);
  t2 = _mm_srli_si128(t0, 8);
  in[2] = _mm_xor_si128(in[2], t2);
  out[1] = _mm_xor_si128(in[1], t1);
  t0 = _mm_clmulepi64_si128(in[3], p, 0x00);
  out[1] = _mm_xor_si128(out[1], t0);

  t0 = _mm_clmulepi64_si128(in[2], p, 0x01);
  t1 = _mm_slli_si128(t0, 8);
  t2 = _mm_srli_si128(t0, 8);
  out[1] = _mm_xor_si128(out[1], t2);
  out[0] = _mm_xor_si128(in[0], t1);
  t0 = _mm_clmulepi64_si128(in[2], p, 0x00);
  out[0] = _mm_xor_si128(out[0], t0); 

}
inline void gf256mul(__m128i *out, const __m128i *in1, const __m128i *in2) {
  __m128i tmp[4];
  clmul_schoolbook_256(tmp, in1, in2);
  reduce_clmul_256(out, tmp);
}
inline void gf256sqr(__m128i *out, const __m128i *in) {
  __m128i tmp[4];
  sqr_256(tmp, in);
  reduce_clmul_256(out, tmp);
}
inline void gf256add(__m128i *out, const __m128i *in1, const __m128i *in2) {
  out[0] = _mm_xor_si128(in1[0], in2[0]);
  out[1] = _mm_xor_si128(in1[1], in2[1]);
}
inline void gf256add(__m256i *out, const __m256i *in1, const __m256i *in2) {
  out[0] = _mm256_xor_si256(in1[0], in2[0]);
}

// 512 field
inline void clmul_schoolbook_512(__m128i out[8], const __m128i a[4], const __m128i b[4]) {

  // Let's do karatsuba instead!!
  // Karatsuba multiplication.
  // x3 x2 x1 x0 -> 512 bits
  // ----- -----
  //   a1    a0
  // y3 y2 y1 y0 -> 512 bits
  // ----- -----
  //   b1    b0

  // (a1 + a0) * (b1 + b0) + a1*b1 + a0*b0
  // (sum xi) *  (sum yi) +   (M2) + (M1)
  // ---------------------
  //           (M3)

  // Z0
  // a0*b0 (M1) part, this should be 256 bit multiplication
  __m128i a0b0[4];
  clmul_schoolbook_256(a0b0, &a[0], &b[0]);
  // a0*b0 ends

  // Z2
  // a1*b1 (M2) part, this should be 256 bit karatsuba multiplication
  __m128i a1b1[4];
  clmul_schoolbook_256(a1b1, &a[2], &b[2]);
  // a1*b1 ends

  // Z3
  // (M3) part
  __m128i asum[2], bsum[2];
  asum[0] = _mm_xor_si128(a[0], a[2]);
  asum[1] = _mm_xor_si128(a[1], a[3]);
  bsum[0] = _mm_xor_si128(b[0], b[2]);
  bsum[1] = _mm_xor_si128(b[1], b[3]);
  __m128i asumbsum[4];
  clmul_schoolbook_256(asumbsum, &asum[0], &bsum[0]);

  // Z1 = Z3 + Z2 + Z0
  asumbsum[0] = _mm_xor_si128(asumbsum[0], _mm_xor_si128(a0b0[0], a1b1[0]));
  asumbsum[1] = _mm_xor_si128(asumbsum[1], _mm_xor_si128(a0b0[1], a1b1[1]));
  asumbsum[2] = _mm_xor_si128(asumbsum[2], _mm_xor_si128(a0b0[2], a1b1[2]));
  asumbsum[3] = _mm_xor_si128(asumbsum[3], _mm_xor_si128(a0b0[3], a1b1[3]));


  // out = z2*X^2m + z1*X^m + z0
  out[0] = a0b0[0];
  out[1] = a0b0[1];
  out[2] = a0b0[2];
  out[3] = a0b0[3];

  out[2] = _mm_xor_si128(out[2], asumbsum[0]);
  out[3] = _mm_xor_si128(out[3], asumbsum[1]);
  out[4] = asumbsum[2];
  out[5] = asumbsum[3];

  out[4] = _mm_xor_si128(out[4], a1b1[0]);
  out[5] = _mm_xor_si128(out[5], a1b1[1]);
  out[6] = a1b1[2];
  out[7] = a1b1[3];


  // uint64_t nums[2];
  // _mm_storeu_si128((__m128i*)nums, out[0]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;
  
  // _mm_storeu_si128((__m128i*)nums, out[1]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;

  // _mm_storeu_si128((__m128i*)nums, out[2]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;
  
  // _mm_storeu_si128((__m128i*)nums, out[3]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;

  //  _mm_storeu_si128((__m128i*)nums, out[4]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;

  //  _mm_storeu_si128((__m128i*)nums, out[5]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;

  //  _mm_storeu_si128((__m128i*)nums, out[6]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;

  //  _mm_storeu_si128((__m128i*)nums, out[7]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;
  // std::cout << std::endl;
  // std::cout << std::endl;

}
inline void combine_si128s(__m128i* out, const __m128i* in, size_t n)
{
    out[0] = _mm_xor_si128(in[0], _mm_slli_si128(in[1], 8));
    for (size_t i = 1; i < n / 2; ++i)
        out[i] = _mm_xor_si128(in[2 * i], _mm_alignr_epi8(in[2 * i + 1], in[2 * i - 1], 8));
    if (n % 2)
        out[n / 2] = _mm_xor_si128(in[n - 1], _mm_srli_si128(in[n - 2], 8));
    else
        out[n / 2] = _mm_srli_si128(in[n - 1], 8);
}
inline void reduce_clmul_512(__m128i out[4], __m128i in[8]) {
  
  // modulus = x^512 + x^8 + x^5 + x^2 + 1

  __m128i p = _mm_set_epi64x(0, 0x125);
    __m128i xmod[8];

  xmod[0] = _mm_set_epi64x(0, 0);
  xmod[1] = _mm_clmulepi64_si128(in[4], p, 0x01);
  xmod[2] = _mm_clmulepi64_si128(in[5], p, 0x00);
  xmod[3] = _mm_clmulepi64_si128(in[5], p, 0x01);
  xmod[4] = _mm_clmulepi64_si128(in[6], p, 0x00);
  xmod[5] = _mm_clmulepi64_si128(in[6], p, 0x01);
  xmod[6] = _mm_clmulepi64_si128(in[7], p, 0x00);
  xmod[7] = _mm_clmulepi64_si128(in[7], p, 0x01);

  __m128i xmod_combined[5];
  combine_si128s(xmod_combined, xmod, 8);

  for (size_t i = 0; i < 5; ++i) {
    xmod_combined[i] = _mm_xor_si128(xmod_combined[i], in[i]);
  }
  xmod_combined[0] =
                _mm_xor_si128(xmod_combined[0], 
                              _mm_clmulepi64_si128(xmod_combined[4], p, 0x00));

  for (size_t i = 0; i < 4; ++i) {
    out[i] = xmod_combined[i];
  }

  // uint64_t nums[2];

  // _mm_storeu_si128((__m128i*)nums, out[0]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;
  
  // _mm_storeu_si128((__m128i*)nums, out[1]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;

  // _mm_storeu_si128((__m128i*)nums, out[2]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;
  
  // _mm_storeu_si128((__m128i*)nums, out[3]);

  // std::cout << "u64: ";
  // for (int i = 0; i < 2; ++i) {
  //     std::cout << nums[i] << " ";
  // }
  // std::cout << std::endl;

}
inline void gf512mul(__m128i *out, const __m128i *in1, const __m128i *in2) {
  // __m128i tmp[8];
  // clmul_schoolbook_512(tmp, in1, in2);
  // reduce_clmul(out, tmp);

  __m128i prod[7];
  deg3_clmul(prod, in1, in2);
  // deg3_reduce(prod);
  out[0] = prod[0];
  out[1] = prod[1];
  out[2] = prod[2];
  out[3] = prod[3];
}
inline void gf512sqr(__m128i *out, const __m128i *in) {
  // __m128i tmp[8];
  // // TODO: Do square!!
  // clmul_schoolbook_512(tmp, in, in);
  // reduce_clmul(out, tmp);

  __m128i prod[7];
  deg3_clmul(prod, in, in);
  // deg3_reduce(prod);
  out[0] = prod[0];
  out[1] = prod[1];
  out[2] = prod[2];
  out[3] = prod[3];
}
inline void gf512add(__m128i *out, const __m128i *in1, const __m128i *in2) {
  out[0] = _mm_xor_si128(in1[0], in2[0]);
  out[1] = _mm_xor_si128(in1[1], in2[1]);
  out[2] = _mm_xor_si128(in1[2], in2[2]);
  out[3] = _mm_xor_si128(in1[3], in2[3]);
}
inline void gf512add(__m256i *out, const __m256i *in1, const __m256i *in2) {
  out[0] = _mm256_xor_si256(in1[0], in2[0]);
  out[1] = _mm256_xor_si256(in1[1], in2[1]);
}
/* static inline __m256i mm256_compute_mask(const uint64_t idx, const size_t bit) {
  return _mm256_set1_epi64x(-((idx >> bit) & 1));
} */

} // namespace

namespace field {
class GF2_512;
class GF2_256;
} // namespace field

namespace field {

  class GF2_256 {
    alignas(64) std::array<uint64_t, 8> data;

    // helper functions for sse stuff
    inline __m128i *as_m128i() {
      return reinterpret_cast<__m128i *>(data.data());
    };
    inline const __m128i *as_const_m128i() const {
      return reinterpret_cast<const __m128i *>(data.data());
    };
    // helper functions for avx2 stuff
    inline __m256i *as_m256i() {
      return reinterpret_cast<__m256i *>(data.data());
    };
    inline const __m256i *as_const_m256i() const {
      return reinterpret_cast<const __m256i *>(data.data());
    };

  public:
    constexpr static size_t BYTE_SIZE = 64;
    constexpr GF2_256() : data{} {};
    constexpr GF2_256(uint64_t data) : data{data, 0, 0, 0} {}
    constexpr GF2_256(std::array<uint64_t, 8> data) : data{data} {}
    GF2_256(std::string hex_string);
    GF2_256(const GF2_256 &other) = default;
    ~GF2_256() = default;
    GF2_256 &operator=(const GF2_256 &other) = default;

    inline void clear() { data = {}; }
    inline bool is_zero() const {
      return data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0;
    }
    inline void set_coeff(size_t idx) { data[idx / 64] |= (1ULL << (idx % 64)); }
    GF2_256 operator+(const GF2_256 &other) const;
    GF2_256 &operator+=(const GF2_256 &other);
    GF2_256 operator-(const GF2_256 &other) const;
    GF2_256 &operator-=(const GF2_256 &other);
    GF2_256 operator*(const GF2_256 &other) const;
    GF2_256 &operator*=(const GF2_256 &other);
    bool operator==(const GF2_256 &other) const;
    bool operator!=(const GF2_256 &other) const;

    GF2_256 inverse() const;
    // GF2_256 inverse_slow() const;
    
    GF2_256 multiply_with_GF2_matrix(const uint8_t* matrix) const;
    // GF2_256 multiply_with_GF2_matrix(const std::array<uint64_t, 16> *matrix) const;
    // GF2_256 multiply_with_transposed_GF2_matrix(const std::array<uint64_t, 4> *matrix) const;

    void to_bytes(uint8_t *out) const;
    void from_bytes(const uint8_t *in);

    // friend GF2_256(::dot_product)(const std::vector<field::GF2_256> &lhs,
    //                               const std::vector<field::GF2_256> &rhs);
    // friend std::ostream &(::operator<<)(std::ostream &os,
    //                                     const field::GF2_256 &ele);
  };

  class GF2_512 {
    alignas(64) std::array<uint64_t, 8> data;

    // helper functions for sse stuff
    inline __m128i *as_m128i() {
      return reinterpret_cast<__m128i *>(data.data());
    };
    inline const __m128i *as_const_m128i() const {
      return reinterpret_cast<const __m128i *>(data.data());
    };
    // helper functions for avx2 stuff
    inline __m256i *as_m256i() {
      return reinterpret_cast<__m256i *>(data.data());
    };
    inline const __m256i *as_const_m256i() const {
      return reinterpret_cast<const __m256i *>(data.data());
    };

  public:
    constexpr static size_t BYTE_SIZE = 64;
    constexpr GF2_512() : data{} {};
    constexpr GF2_512(uint64_t data) : data{data, 0, 0, 0, 0, 0, 0, 0} {}
    constexpr GF2_512(std::array<uint64_t, 8> data) : data{data} {}
    GF2_512(std::string hex_string);
    GF2_512(const GF2_512 &other) = default;
    ~GF2_512() = default;
    GF2_512 &operator=(const GF2_512 &other) = default;

    inline void clear() { data = {}; }
    inline bool is_zero() const {
      return data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0;
    }
    inline void set_coeff(size_t idx) { data[idx / 64] |= (1ULL << (idx % 64)); }
    GF2_512 operator+(const GF2_512 &other) const;
    GF2_512 &operator+=(const GF2_512 &other);
    GF2_512 operator-(const GF2_512 &other) const;
    GF2_512 &operator-=(const GF2_512 &other);
    GF2_512 operator*(const GF2_512 &other) const;
    GF2_512 &operator*=(const GF2_512 &other);
    bool operator==(const GF2_512 &other) const;
    bool operator!=(const GF2_512 &other) const;

    GF2_512 inverse() const;
    // GF2_512 inverse_slow() const;
    
    GF2_512 multiply_with_GF2_matrix(const uint8_t* matrix) const;
    // GF2_512 multiply_with_GF2_matrix(const std::array<uint64_t, 16> *matrix) const;
    // GF2_512 multiply_with_transposed_GF2_matrix(
    //     const std::array<uint64_t, 4> *matrix) const;

    void to_bytes(uint8_t *out) const;
    void from_bytes(const uint8_t *in);

    // friend GF2_512(::dot_product)(const std::vector<field::GF2_512> &lhs,
    //                               const std::vector<field::GF2_512> &rhs);
    // friend std::ostream &(::operator<<)(std::ostream &os,
    //                                     const field::GF2_512 &ele);
  };

};

namespace field {

// 256 part
// Functions taken form the rainier implementation
inline GF2_256::GF2_256(std::string hex_string) {
  // check if hex_string start with 0x or 0X
  if (hex_string.rfind("0x", 0) == 0 || hex_string.rfind("0X", 0) == 0) {
    hex_string = hex_string.substr(2);
  } else {
    throw std::runtime_error("input needs to be a hex number");
  }
  constexpr size_t num_hex_chars = 256 / 4;
  if (hex_string.length() > num_hex_chars)
    throw std::runtime_error("input hex is too large");
  // pad to 256 bit
  hex_string.insert(hex_string.begin(), num_hex_chars - hex_string.length(),
                    '0');
  // high 64 bit
  uint64_t high = std::stoull(hex_string.substr(0, 64 / 4), nullptr, 16);
  // mid_hi 64 bit
  uint64_t mid_hi = std::stoull(hex_string.substr(64 / 4, 64 / 4), nullptr, 16);
  // mid_lo 64 bit
  uint64_t mid_lo =
      std::stoull(hex_string.substr(128 / 4, 64 / 4), nullptr, 16);
  // low 64 bit
  uint64_t low = std::stoull(hex_string.substr(192 / 4, 64 / 4), nullptr, 16);
  data[0] = low;
  data[1] = mid_lo;
  data[2] = mid_hi;
  data[3] = high;
}
inline GF2_256 GF2_256::operator+(const GF2_256 &other) const {
  GF2_256 result;
  gf256add(result.as_m256i(), this->as_const_m256i(), other.as_const_m256i());
  return result;
}
inline GF2_256 &GF2_256::operator+=(const GF2_256 &other) {
  gf256add(this->as_m256i(), this->as_const_m256i(), other.as_const_m256i());
  return *this;
}
inline GF2_256 GF2_256::operator-(const GF2_256 &other) const {
  GF2_256 result;
  gf256add(result.as_m256i(), this->as_const_m256i(), other.as_const_m256i());
  return result;
}
inline GF2_256 &GF2_256::operator-=(const GF2_256 &other) {
  gf256add(this->as_m256i(), this->as_const_m256i(), other.as_const_m256i());
  return *this;
}
inline GF2_256 GF2_256::operator*(const GF2_256 &other) const {
  GF2_256 result;
  gf256mul(result.as_m128i(), this->as_const_m128i(), other.as_const_m128i());
  return result;
}
inline GF2_256 &GF2_256::operator*=(const GF2_256 &other) {
  gf256mul(this->as_m128i(), this->as_const_m128i(), other.as_const_m128i());
  return *this;
}
inline bool GF2_256::operator==(const GF2_256 &other) const {
  return this->data == other.data;
}
inline bool GF2_256::operator!=(const GF2_256 &other) const {
  return this->data != other.data;
}
inline GF2_256 GF2_256::inverse() const {
  constexpr size_t u[11] = {1, 2, 3, 6, 12, 15, 30, 60, 120, 240, 255};
  constexpr size_t u_len = sizeof(u) / sizeof(u[0]);
  // q = u[i] - u[i - 1] should give us the corresponding values
  // (1, 1, 3, 6, 3, 15, 30, 60, 120, 15), which will have corresponding
  // indexes
  constexpr size_t q_index[u_len - 1] = {0, 0, 2, 3, 2, 5, 6, 7, 8, 5};
  __m128i b[u_len][2];

  b[0][0] = this->as_const_m128i()[0];
  b[0][1] = this->as_const_m128i()[1];

  for (size_t i = 1; i < u_len; ++i) {

    __m128i b_p[2] = {b[i - 1][0], b[i - 1][1]};
    __m128i b_q[2] = {b[q_index[i - 1]][0], b[q_index[i - 1]][1]};

    for (size_t m = u[q_index[i - 1]]; m; --m) {
      gf256sqr(b_p, b_p);
    }

    gf256mul(b[i], b_p, b_q);
  }

  GF2_256 out;
  gf256sqr(out.as_m128i(), b[u_len - 1]);

  return out;
}
inline GF2_256 GF2_256::multiply_with_GF2_matrix(const uint8_t* matrix) const {
  
  GF2_256 result;

  for (size_t j = 0; j < 256; j++) {

    const uint64_t *A = (uint64_t*)(matrix + j*64);

    uint64_t bit =
        _mm_popcnt_u64((this->data[0] & A[0]) ^ (this->data[1] & A[1]) ^
                        (this->data[2] & A[2]) ^ (this->data[3] & A[3])) & 1;
    
    result.data[j/64] |= (bit << j%64);

  }

  return result;
}
/* // TODO: Implement the 512-bits fast transposed matrix
GF2_256 GF2_256::multiply_with_transposed_GF2_matrix(const std::array<uint64_t, 4> *matrix) const {
  const uint64_t *vptr = this->data.data();
  const __m256i *Ablock = reinterpret_cast<const __m256i *>(matrix->data());

  __m256i cval[2] = {_mm256_setzero_si256(), _mm256_setzero_si256()};
  for (unsigned int w = 4; w; --w, ++vptr) {
    uint64_t idx = *vptr;
    for (unsigned int i = sizeof(uint64_t) * 8; i;
         i -= 4, idx >>= 4, Ablock += 4) {
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[0], mm256_compute_mask(idx, 0)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[1], mm256_compute_mask(idx, 1)));
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[2], mm256_compute_mask(idx, 2)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[3], mm256_compute_mask(idx, 3)));
    }
  }
  GF2_256 result;
  result.as_m256i()[0] = _mm256_xor_si256(cval[0], cval[1]);
  return result;
} */
inline void GF2_256::to_bytes(uint8_t *out) const {
  uint64_t le_data = htole64(data[0]);
  memcpy(out, (uint8_t *)(&le_data), sizeof(uint64_t));
  le_data = htole64(data[1]);
  memcpy(out + sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));
  le_data = htole64(data[2]);
  memcpy(out + 2 * sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));
  le_data = htole64(data[3]);
  memcpy(out + 3 * sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));
}
inline void GF2_256::from_bytes(const uint8_t *in) {
  uint64_t tmp;
  memcpy((uint8_t *)(&tmp), in, sizeof(uint64_t));
  data[0] = le64toh(tmp);
  memcpy((uint8_t *)(&tmp), in + sizeof(uint64_t), sizeof(uint64_t));
  data[1] = le64toh(tmp);
  memcpy((uint8_t *)(&tmp), in + 2 * sizeof(uint64_t), sizeof(uint64_t));
  data[2] = le64toh(tmp);
  memcpy((uint8_t *)(&tmp), in + 3 * sizeof(uint64_t), sizeof(uint64_t));
  data[3] = le64toh(tmp);
}

// 512 part
inline GF2_512::GF2_512(std::string hex_string) {
  // check if hex_string start with 0x or 0X
  if (hex_string.rfind("0x", 0) == 0 || hex_string.rfind("0X", 0) == 0) {
    hex_string = hex_string.substr(2);
  } else {
    throw std::runtime_error("input needs to be a hex number");
  }
  constexpr size_t num_hex_chars = 512 / 4;
  if (hex_string.length() > num_hex_chars)
    throw std::runtime_error("input hex is too large");
  // pad to 512 bit
  hex_string.insert(hex_string.begin(), num_hex_chars - hex_string.length(),
                    '0');
  // Getting bits MSB to LSB (u7, u6, u5, u4, u3, u2, u1, u0)
  data[7] = std::stoull(hex_string.substr(0, 64 / 4), nullptr, 16);
  data[6] = std::stoull(hex_string.substr(64 / 4, 64 / 4), nullptr, 16);
  data[5] = std::stoull(hex_string.substr(128 / 4, 64 / 4), nullptr, 16);
  data[4] = std::stoull(hex_string.substr(192 / 4, 64 / 4), nullptr, 16);

  data[3] = std::stoull(hex_string.substr(256 / 4, 64 / 4), nullptr, 16);
  data[2] = std::stoull(hex_string.substr(320 / 4, 64 / 4), nullptr, 16);
  data[1] = std::stoull(hex_string.substr(384 / 4, 64 / 4), nullptr, 16);
  data[0] = std::stoull(hex_string.substr(448 / 4, 64 / 4), nullptr, 16);

}
inline GF2_512 GF2_512::operator+(const GF2_512 &other) const {
  GF2_512 result;
  gf512add(result.as_m128i(), this->as_const_m128i(), other.as_const_m128i());
  return result;
}
inline GF2_512 &GF2_512::operator+=(const GF2_512 &other) {
  gf512add(this->as_m128i(), this->as_const_m128i(), other.as_const_m128i());
  return *this;
}
inline GF2_512 GF2_512::operator-(const GF2_512 &other) const {
  GF2_512 result;
  gf512add(result.as_m128i(), this->as_const_m128i(), other.as_const_m128i());
  return result;
}
inline GF2_512 &GF2_512::operator-=(const GF2_512 &other) {
  gf512add(this->as_m128i(), this->as_const_m128i(), other.as_const_m128i());
  return *this;
}
inline GF2_512 GF2_512::operator*(const GF2_512 &other) const {
  GF2_512 result;
  gf512mul(result.as_m128i(), this->as_const_m128i(), other.as_const_m128i());
  return result;
}
inline GF2_512 &GF2_512::operator*=(const GF2_512 &other) {
  gf512mul(this->as_m128i(), this->as_const_m128i(), other.as_const_m128i());
  return *this;
}
inline bool GF2_512::operator==(const GF2_512 &other) const {
  return this->data == other.data;
}
inline bool GF2_512::operator!=(const GF2_512 &other) const {
  return this->data != other.data;
}
// NOTE: Generated from https://www.numbersaplenty.com/ac/fr15.html
inline GF2_512 GF2_512::inverse() const {
  constexpr size_t u[13] = {1, 2, 3, 4, 7, 14, 21, 42, 63, 126, 252, 259, 511};
  constexpr size_t u_len = sizeof(u) / sizeof(u[0]);
  // q = u[i] - u[i - 1] should give us the corresponding values
  // (1, 1, 1, 3, 7, 7, 21, 21, 63, 126, 7, 252), which will have corresponding indexes
  constexpr size_t q_index[u_len - 1] = {0, 0, 0, 2, 4, 4, 6, 6, 8, 9, 4, 10};
  __m128i b[u_len][4];

  b[0][0] = this->as_const_m128i()[0];
  b[0][1] = this->as_const_m128i()[1];
  b[0][2] = this->as_const_m128i()[2];
  b[0][3] = this->as_const_m128i()[3];

  for (size_t i = 1; i < u_len; ++i) {

    __m128i b_p[4] = {b[i - 1][0], b[i - 1][1], b[i - 1][2], b[i - 1][3]};
    __m128i b_q[4] = {b[q_index[i - 1]][0], b[q_index[i - 1]][1], b[q_index[i - 1]][2], b[q_index[i - 1]][3]};

    for (size_t m = u[q_index[i - 1]]; m; --m) {
      gf512sqr(b_p, b_p);
    }

    gf512mul(b[i], b_p, b_q);
  }

  GF2_512 out;
  gf512sqr(out.as_m128i(), b[u_len - 1]);

  return out;
}
// NOTE: Stored coloumn major
inline GF2_512
GF2_512::multiply_with_GF2_matrix(const uint8_t* matrix) const {

  GF2_512 result;

  for (size_t j = 0; j < 512; j++) {
        
    const uint64_t *A = (uint64_t*)(matrix + j*64);

    uint64_t bit =
        _mm_popcnt_u64((this->data[0] & A[0]) ^ (this->data[1] & A[1]) ^ (this->data[2] & A[2]) ^ (this->data[3] & A[3]) 
        ^ (this->data[4] & A[4]) ^ (this->data[5] & A[5]) ^ (this->data[6] & A[6]) ^ (this->data[7] & A[7])) & 1;

    result.data[j/64] |= (bit << j%64);
  }

  return result;
}
/* // TODO: Implement the 512-bits fast transposed matrix
GF2_512
GF2_512::multiply_with_transposed_GF2_matrix(
    const std::array<uint64_t, 4> *matrix) const {
  const uint64_t *vptr = this->data.data();
  const __m256i *Ablock = reinterpret_cast<const __m256i *>(matrix->data());

  __m256i cval[2] = {_mm256_setzero_si256(), _mm256_setzero_si256()};
  for (unsigned int w = 4; w; --w, ++vptr) {
    uint64_t idx = *vptr;
    for (unsigned int i = sizeof(uint64_t) * 8; i;
         i -= 4, idx >>= 4, Ablock += 4) {
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[0], mm256_compute_mask(idx, 0)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[1], mm256_compute_mask(idx, 1)));
      cval[0] = _mm256_xor_si256(
          cval[0], _mm256_and_si256(Ablock[2], mm256_compute_mask(idx, 2)));
      cval[1] = _mm256_xor_si256(
          cval[1], _mm256_and_si256(Ablock[3], mm256_compute_mask(idx, 3)));
    }
  }
  GF2_512 result;
  result.as_m256i()[0] = _mm256_xor_si256(cval[0], cval[1]);
  return result;
} */
inline void GF2_512::to_bytes(uint8_t *out) const {

  // TODO: Switch back to le64toh ???

  // uint64_t le_data = htole64(data[0]);
  uint64_t le_data = data[0];
  memcpy(out, (uint8_t *)(&le_data), sizeof(uint64_t));

  // le_data = htole64(data[1]);
  le_data = data[1];
  memcpy(out + sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));

  // le_data = htole64(data[2]);
  le_data = data[2];
  memcpy(out + 2 * sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));

  // le_data = htole64(data[3]);
  le_data = data[3];
  memcpy(out + 3 * sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));

  // le_data = htole64(data[4]);
  le_data = data[4];
  memcpy(out + 4 * sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));

  // le_data = htole64(data[5]);
  le_data = data[5];
  memcpy(out + 5 * sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));

  // le_data = htole64(data[6]);
  le_data = data[6];
  memcpy(out + 6 * sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));

  // le_data = htole64(data[7]);
  le_data = data[7];
  memcpy(out + 7 * sizeof(uint64_t), (uint8_t *)(&le_data), sizeof(uint64_t));

}
inline void GF2_512::from_bytes(const uint8_t *in) {

  // TODO: Switch back to le64toh ???
  
  uint64_t tmp;
  memcpy((uint8_t *)(&tmp), in, sizeof(uint64_t));
  // data[0] = le64toh(tmp);
  data[0] = tmp;

  memcpy((uint8_t *)(&tmp), in + sizeof(uint64_t), sizeof(uint64_t));
  // data[1] = le64toh(tmp);
  data[1] = tmp;

  memcpy((uint8_t *)(&tmp), in + 2 * sizeof(uint64_t), sizeof(uint64_t));
  // data[2] = le64toh(tmp);
  data[2] = tmp;

  memcpy((uint8_t *)(&tmp), in + 3 * sizeof(uint64_t), sizeof(uint64_t));
  // data[3] = le64toh(tmp);
  data[3] = tmp;

  memcpy((uint8_t *)(&tmp), in + 4 * sizeof(uint64_t), sizeof(uint64_t));
  // data[4] = le64toh(tmp);
  data[4] = tmp;

  memcpy((uint8_t *)(&tmp), in + 5 * sizeof(uint64_t), sizeof(uint64_t));
  // data[5] = le64toh(tmp);
  data[5] = tmp;

  memcpy((uint8_t *)(&tmp), in + 6 * sizeof(uint64_t), sizeof(uint64_t));
  // data[6] = le64toh(tmp);
  data[6] = tmp;

  memcpy((uint8_t *)(&tmp), in + 7 * sizeof(uint64_t), sizeof(uint64_t));
  // data[7] = le64toh(tmp);
  data[7] = tmp;

}

} // namespace field

// 256
inline std::vector<field::GF2_256> operator+(const std::vector<field::GF2_256> &lhs, const std::vector<field::GF2_256> &rhs) {
  if (lhs.size() != rhs.size())
    throw std::runtime_error("adding vectors of different sizes");

  std::vector<field::GF2_256> result(lhs);
  for (size_t i = 0; i < lhs.size(); i++)
    result[i] += rhs[i];

  return result;
}
inline std::vector<field::GF2_256> &operator+=(std::vector<field::GF2_256> &lhs, const std::vector<field::GF2_256> &rhs) {
  if (lhs.size() != rhs.size())
    throw std::runtime_error("adding vectors of different sizes");

  for (size_t i = 0; i < lhs.size(); i++)
    lhs[i] += rhs[i];

  return lhs;
}
inline std::vector<field::GF2_256> operator*(const std::vector<field::GF2_256> &lhs, const field::GF2_256 &rhs) {
  std::vector<field::GF2_256> result(lhs);
  for (size_t i = 0; i < lhs.size(); i++)
    result[i] *= rhs;

  return result;
}
inline std::vector<field::GF2_256> operator*(const field::GF2_256 &lhs, const std::vector<field::GF2_256> &rhs) {
  return rhs * lhs;
}
// naive polynomial multiplication
inline std::vector<field::GF2_256> operator*(const std::vector<field::GF2_256> &lhs, const std::vector<field::GF2_256> &rhs) {

  std::vector<field::GF2_256> result(lhs.size() + rhs.size() - 1);
  for (size_t i = 0; i < lhs.size(); i++)
    for (size_t j = 0; j < rhs.size(); j++)
      result[i + j] += lhs[i] * rhs[j];

  return result;
}

// 512
inline std::vector<field::GF2_512> operator+(const std::vector<field::GF2_512> &lhs, const std::vector<field::GF2_512> &rhs) {
  if (lhs.size() != rhs.size())
    throw std::runtime_error("adding vectors of different sizes");

  std::vector<field::GF2_512> result(lhs);
  for (size_t i = 0; i < lhs.size(); i++)
    result[i] += rhs[i];

  return result;
}
inline std::vector<field::GF2_512> &operator+=(std::vector<field::GF2_512> &lhs, const std::vector<field::GF2_512> &rhs) {
  if (lhs.size() != rhs.size())
    throw std::runtime_error("adding vectors of different sizes");

  for (size_t i = 0; i < lhs.size(); i++)
    lhs[i] += rhs[i];

  return lhs;
}
inline std::vector<field::GF2_512> operator*(const std::vector<field::GF2_512> &lhs, const field::GF2_512 &rhs) {
  std::vector<field::GF2_512> result(lhs);
  for (size_t i = 0; i < lhs.size(); i++)
    result[i] *= rhs;

  return result;
}
inline std::vector<field::GF2_512> operator*(const field::GF2_512 &lhs, const std::vector<field::GF2_512> &rhs) {
  return rhs * lhs;
}
// naive polynomial multiplication
inline std::vector<field::GF2_512> operator*(const std::vector<field::GF2_512> &lhs, const std::vector<field::GF2_512> &rhs) {

  std::vector<field::GF2_512> result(lhs.size() + rhs.size() - 1);
  for (size_t i = 0; i < lhs.size(); i++)
    for (size_t j = 0; j < rhs.size(); j++)
      result[i + j] += lhs[i] * rhs[j];

  return result;
}

// 256
inline std::vector<field::GF2_256> operator+(const std::vector<field::GF2_256> &lhs, const std::vector<field::GF2_256> &rhs);
inline std::vector<field::GF2_256> &operator+=(std::vector<field::GF2_256> &self, const std::vector<field::GF2_256> &rhs);
inline std::vector<field::GF2_256> operator*(const std::vector<field::GF2_256> &lhs, const field::GF2_256 &rhs);
inline std::vector<field::GF2_256> operator*(const field::GF2_256 &lhs, const std::vector<field::GF2_256> &rhs);
inline std::vector<field::GF2_256> operator*(const std::vector<field::GF2_256> &lhs, const std::vector<field::GF2_256> &rhs);

// 512
inline std::vector<field::GF2_512> operator+(const std::vector<field::GF2_512> &lhs, const std::vector<field::GF2_512> &rhs);
inline std::vector<field::GF2_512> &operator+=(std::vector<field::GF2_512> &self, const std::vector<field::GF2_512> &rhs);
inline std::vector<field::GF2_512> operator*(const std::vector<field::GF2_512> &lhs, const field::GF2_512 &rhs);
inline std::vector<field::GF2_512> operator*(const field::GF2_512 &lhs, const std::vector<field::GF2_512> &rhs);
inline std::vector<field::GF2_512> operator*(const std::vector<field::GF2_512> &lhs, const std::vector<field::GF2_512> &rhs);

#endif