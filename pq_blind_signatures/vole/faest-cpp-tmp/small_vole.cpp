#include "small_vole.inc"

namespace faest
{

// clang-format off

#if defined WITH_KECCAK
// ----- v1 -----
template void vole_sender<v1::keccak_then_mayo_128_s>(unsigned int, const block_secpar<v1::keccak_then_mayo_128_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v1::keccak_then_mayo_128_f>(unsigned int, const block_secpar<v1::keccak_then_mayo_128_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v1::keccak_then_mayo_192_s>(unsigned int, const block_secpar<v1::keccak_then_mayo_192_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v1::keccak_then_mayo_192_f>(unsigned int, const block_secpar<v1::keccak_then_mayo_192_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v1::keccak_then_mayo_256_s>(unsigned int, const block_secpar<v1::keccak_then_mayo_256_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v1::keccak_then_mayo_256_f>(unsigned int, const block_secpar<v1::keccak_then_mayo_256_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);

// ----- v2 -----
template void vole_sender<v2::keccak_then_mayo_128_s>(unsigned int, const block_secpar<v2::keccak_then_mayo_128_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v2::keccak_then_mayo_128_f>(unsigned int, const block_secpar<v2::keccak_then_mayo_128_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v2::keccak_then_mayo_192_s>(unsigned int, const block_secpar<v2::keccak_then_mayo_192_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v2::keccak_then_mayo_192_f>(unsigned int, const block_secpar<v2::keccak_then_mayo_192_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v2::keccak_then_mayo_256_s>(unsigned int, const block_secpar<v2::keccak_then_mayo_256_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v2::keccak_then_mayo_256_f>(unsigned int, const block_secpar<v2::keccak_then_mayo_256_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
#endif

#if defined WITH_RAINHASH
// ----- v1 -----
template void vole_sender<v1::rainhash_then_mayo_128_s>(unsigned int, const block_secpar<v1::rainhash_then_mayo_128_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v1::rainhash_then_mayo_128_f>(unsigned int, const block_secpar<v1::rainhash_then_mayo_128_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);

// ----- v2 -----
template void vole_sender<v2::rainhash_then_mayo_128_s>(unsigned int, const block_secpar<v2::rainhash_then_mayo_128_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
template void vole_sender<v2::rainhash_then_mayo_128_f>(unsigned int, const block_secpar<v2::rainhash_then_mayo_128_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, vole_block* __restrict__);
#endif

#if defined WITH_KECCAK
// ----- v1 -----
template void vole_receiver<v1::keccak_then_mayo_128_s>(unsigned int, const block_secpar<v1::keccak_then_mayo_128_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v1::keccak_then_mayo_128_f>(unsigned int, const block_secpar<v1::keccak_then_mayo_128_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v1::keccak_then_mayo_192_s>(unsigned int, const block_secpar<v1::keccak_then_mayo_192_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v1::keccak_then_mayo_192_f>(unsigned int, const block_secpar<v1::keccak_then_mayo_192_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v1::keccak_then_mayo_256_s>(unsigned int, const block_secpar<v1::keccak_then_mayo_256_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v1::keccak_then_mayo_256_f>(unsigned int, const block_secpar<v1::keccak_then_mayo_256_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);

// ----- v2 -----
template void vole_receiver<v2::keccak_then_mayo_128_s>(unsigned int, const block_secpar<v2::keccak_then_mayo_128_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v2::keccak_then_mayo_128_f>(unsigned int, const block_secpar<v2::keccak_then_mayo_128_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v2::keccak_then_mayo_192_s>(unsigned int, const block_secpar<v2::keccak_then_mayo_192_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v2::keccak_then_mayo_192_f>(unsigned int, const block_secpar<v2::keccak_then_mayo_192_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v2::keccak_then_mayo_256_s>(unsigned int, const block_secpar<v2::keccak_then_mayo_256_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v2::keccak_then_mayo_256_f>(unsigned int, const block_secpar<v2::keccak_then_mayo_256_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
#endif

#if defined WITH_RAINHASH
// ----- v1 -----
template void vole_receiver<v1::rainhash_then_mayo_128_s>(unsigned int, const block_secpar<v1::rainhash_then_mayo_128_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v1::rainhash_then_mayo_128_f>(unsigned int, const block_secpar<v1::rainhash_then_mayo_128_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);

// ----- v2 -----
template void vole_receiver<v2::rainhash_then_mayo_128_s>(unsigned int, const block_secpar<v2::rainhash_then_mayo_128_s::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver<v2::rainhash_then_mayo_128_f>(unsigned int, const block_secpar<v2::rainhash_then_mayo_128_f::secpar_v>* __restrict__, block128, uint32_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
#endif

#if defined WITH_KECCAK
// ----- v1 -----
template void vole_receiver_apply_correction<v1::keccak_then_mayo_128_s>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v1::keccak_then_mayo_128_f>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v1::keccak_then_mayo_192_s>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v1::keccak_then_mayo_192_f>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v1::keccak_then_mayo_256_s>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v1::keccak_then_mayo_256_f>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);

// ----- v2 -----
template void vole_receiver_apply_correction<v2::keccak_then_mayo_128_s>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v2::keccak_then_mayo_128_f>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v2::keccak_then_mayo_192_s>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v2::keccak_then_mayo_192_f>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v2::keccak_then_mayo_256_s>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v2::keccak_then_mayo_256_f>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
#endif

#if defined WITH_RAINHASH
// ----- v1 -----
template void vole_receiver_apply_correction<v1::rainhash_then_mayo_128_s>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v1::rainhash_then_mayo_128_f>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
// ----- v2 -----
template void vole_receiver_apply_correction<v2::rainhash_then_mayo_128_s>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
template void vole_receiver_apply_correction<v2::rainhash_then_mayo_128_f>(size_t, size_t, const vole_block* __restrict__, vole_block* __restrict__, const uint8_t* __restrict__);
#endif


// clang-format on

} // namespace faest
