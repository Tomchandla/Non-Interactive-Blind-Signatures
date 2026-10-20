#include "small_vole.inc"

namespace faest
{

// clang-format off
#define NIBS_INST_SMALL_VOLE(P) \
template void vole_sender<P>(unsigned int, const block_secpar<P::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__); \
template void vole_receiver<P>(unsigned int, const block_secpar<P::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__); \
template void vole_receiver_apply_correction<P>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);

NIBS_FOR_EACH_INSTANCE(NIBS_INST_SMALL_VOLE)
// clang-format on

} // namespace faest
