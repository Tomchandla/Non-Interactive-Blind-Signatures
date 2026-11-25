#include "owf_proof.inc"

namespace faest
{

// clang-format off
#define NIBS_INST_OWF(P) \
template void owf_constraints<P, false>(quicksilver_state<P::secpar_v, false, P::OWF_CONSTS::QS_DEGREE>*, const public_key<P>*, unsigned char*); \
template void owf_constraints<P, true>(quicksilver_state<P::secpar_v, true, P::OWF_CONSTS::QS_DEGREE>*, const public_key<P>*, unsigned char*);

NIBS_FOR_EACH_INSTANCE(NIBS_INST_OWF)
// clang-format on

} // namespace faest
