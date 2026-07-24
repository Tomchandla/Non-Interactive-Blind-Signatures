#include "owf_proof.inc"

namespace faest
{

// clang-format off
#if defined WITH_KECCAK
// ----- v1 -----
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_128_s::secpar_v, false, v1::keccak_then_mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_128_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_128_f::secpar_v, false, v1::keccak_then_mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_128_f>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_192_s::secpar_v, false, v1::keccak_then_mayo_192_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_192_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_192_f::secpar_v, false, v1::keccak_then_mayo_192_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_192_f>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_256_s::secpar_v, false, v1::keccak_then_mayo_256_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_256_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_256_f::secpar_v, false, v1::keccak_then_mayo_256_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_256_f>*, unsigned char*);

template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_128_s::secpar_v, true, v1::keccak_then_mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_128_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_128_f::secpar_v, true, v1::keccak_then_mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_128_f>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_192_s::secpar_v, true, v1::keccak_then_mayo_192_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_192_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_192_f::secpar_v, true, v1::keccak_then_mayo_192_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_192_f>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_256_s::secpar_v, true, v1::keccak_then_mayo_256_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_256_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::keccak_then_mayo_256_f::secpar_v, true, v1::keccak_then_mayo_256_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::keccak_then_mayo_256_f>*, unsigned char*);
// ----- v2 -----
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_128_s::secpar_v, false, v2::keccak_then_mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_128_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_128_f::secpar_v, false, v2::keccak_then_mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_128_f>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_192_s::secpar_v, false, v2::keccak_then_mayo_192_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_192_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_192_f::secpar_v, false, v2::keccak_then_mayo_192_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_192_f>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_256_s::secpar_v, false, v2::keccak_then_mayo_256_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_256_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_256_f::secpar_v, false, v2::keccak_then_mayo_256_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_256_f>*, unsigned char*);

template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_128_s::secpar_v, true, v2::keccak_then_mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_128_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_128_f::secpar_v, true, v2::keccak_then_mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_128_f>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_192_s::secpar_v, true, v2::keccak_then_mayo_192_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_192_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_192_f::secpar_v, true, v2::keccak_then_mayo_192_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_192_f>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_256_s::secpar_v, true, v2::keccak_then_mayo_256_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_256_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::keccak_then_mayo_256_f::secpar_v, true, v2::keccak_then_mayo_256_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::keccak_then_mayo_256_f>*, unsigned char*);
#endif

#if defined WITH_RAINHASH
// ----- v1 -----
template void owf_constraints(quicksilver_state<v1::rainhash_then_mayo_128_s::secpar_v, false, v1::rainhash_then_mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::rainhash_then_mayo_128_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::rainhash_then_mayo_128_f::secpar_v, false, v1::rainhash_then_mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::rainhash_then_mayo_128_f>*, unsigned char*);

template void owf_constraints(quicksilver_state<v1::rainhash_then_mayo_128_s::secpar_v, true, v1::rainhash_then_mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::rainhash_then_mayo_128_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v1::rainhash_then_mayo_128_f::secpar_v, true, v1::rainhash_then_mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v1::rainhash_then_mayo_128_f>*, unsigned char*);
// ----- v2 -----
template void owf_constraints(quicksilver_state<v2::rainhash_then_mayo_128_s::secpar_v, false, v2::rainhash_then_mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::rainhash_then_mayo_128_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::rainhash_then_mayo_128_f::secpar_v, false, v2::rainhash_then_mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::rainhash_then_mayo_128_f>*, unsigned char*);

template void owf_constraints(quicksilver_state<v2::rainhash_then_mayo_128_s::secpar_v, true, v2::rainhash_then_mayo_128_s::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::rainhash_then_mayo_128_s>*, unsigned char*);
template void owf_constraints(quicksilver_state<v2::rainhash_then_mayo_128_f::secpar_v, true, v2::rainhash_then_mayo_128_f::OWF_CONSTS::QS_DEGREE>*, const public_key<v2::rainhash_then_mayo_128_f>*, unsigned char*);
#endif


// clang-format on

} // namespace faest
