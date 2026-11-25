#include "vole_commit.inc"

namespace faest
{

// clang-format off
#define NIBS_INST_VOLE_COMMIT(P) \
template void vole_commit<P>(block_secpar<P::secpar_v>, block128, block_secpar<P::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__); \
template bool vole_reconstruct<P>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);

NIBS_FOR_EACH_INSTANCE(NIBS_INST_VOLE_COMMIT)
// clang-format on

} // namespace faest
