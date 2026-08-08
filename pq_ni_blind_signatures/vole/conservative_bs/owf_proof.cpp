#include "owf_proof.inc"

namespace faest
{

// clang-format off

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


// clang-format on

} // namespace faest
