#include "vole_commit.inc"

namespace faest
{

// clang-format off

#if defined WITH_KECCAK

// ----- v1 -----
template void vole_commit<v1::keccak_then_mayo_128_s>(block_secpar<v1::keccak_then_mayo_128_s::secpar_v>, block128, block_secpar<v1::keccak_then_mayo_128_s::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v1::keccak_then_mayo_128_f>(block_secpar<v1::keccak_then_mayo_128_f::secpar_v>, block128, block_secpar<v1::keccak_then_mayo_128_f::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v1::keccak_then_mayo_192_s>(block_secpar<v1::keccak_then_mayo_192_s::secpar_v>, block128, block_secpar<v1::keccak_then_mayo_192_s::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v1::keccak_then_mayo_192_f>(block_secpar<v1::keccak_then_mayo_192_f::secpar_v>, block128, block_secpar<v1::keccak_then_mayo_192_f::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v1::keccak_then_mayo_256_s>(block_secpar<v1::keccak_then_mayo_256_s::secpar_v>, block128, block_secpar<v1::keccak_then_mayo_256_s::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v1::keccak_then_mayo_256_f>(block_secpar<v1::keccak_then_mayo_256_f::secpar_v>, block128, block_secpar<v1::keccak_then_mayo_256_f::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
// ----- v2 -----
template void vole_commit<v2::keccak_then_mayo_128_s>(block_secpar<v2::keccak_then_mayo_128_s::secpar_v>, block128, block_secpar<v2::keccak_then_mayo_128_s::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v2::keccak_then_mayo_128_f>(block_secpar<v2::keccak_then_mayo_128_f::secpar_v>, block128, block_secpar<v2::keccak_then_mayo_128_f::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v2::keccak_then_mayo_192_s>(block_secpar<v2::keccak_then_mayo_192_s::secpar_v>, block128, block_secpar<v2::keccak_then_mayo_192_s::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v2::keccak_then_mayo_192_f>(block_secpar<v2::keccak_then_mayo_192_f::secpar_v>, block128, block_secpar<v2::keccak_then_mayo_192_f::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v2::keccak_then_mayo_256_s>(block_secpar<v2::keccak_then_mayo_256_s::secpar_v>, block128, block_secpar<v2::keccak_then_mayo_256_s::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v2::keccak_then_mayo_256_f>(block_secpar<v2::keccak_then_mayo_256_f::secpar_v>, block128, block_secpar<v2::keccak_then_mayo_256_f::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
#endif

#if defined WITH_RAINHASH
// ----- v2 -----
template void vole_commit<v1::rainhash_then_mayo_128_s>(block_secpar<v1::rainhash_then_mayo_128_s::secpar_v>, block128, block_secpar<v1::rainhash_then_mayo_128_s::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v1::rainhash_then_mayo_128_f>(block_secpar<v1::rainhash_then_mayo_128_f::secpar_v>, block128, block_secpar<v1::rainhash_then_mayo_128_f::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
// ----- v2 -----
template void vole_commit<v2::rainhash_then_mayo_128_s>(block_secpar<v2::rainhash_then_mayo_128_s::secpar_v>, block128, block_secpar<v2::rainhash_then_mayo_128_s::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
template void vole_commit<v2::rainhash_then_mayo_128_f>(block_secpar<v2::rainhash_then_mayo_128_f::secpar_v>, block128, block_secpar<v2::rainhash_then_mayo_128_f::secpar_v>* __restrict__, unsigned char* __restrict__, vole_block* __restrict__, vole_block* __restrict__, uint8_t* __restrict__, uint8_t* __restrict__);
#endif

#if defined WITH_KECCAK
// ----- v1 -----
template bool vole_reconstruct<v1::keccak_then_mayo_128_s>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v1::keccak_then_mayo_128_f>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v1::keccak_then_mayo_192_s>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v1::keccak_then_mayo_192_f>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v1::keccak_then_mayo_256_s>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v1::keccak_then_mayo_256_f>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
// ----- v2 -----
template bool vole_reconstruct<v2::keccak_then_mayo_128_s>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v2::keccak_then_mayo_128_f>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v2::keccak_then_mayo_192_s>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v2::keccak_then_mayo_192_f>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v2::keccak_then_mayo_256_s>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v2::keccak_then_mayo_256_f>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
#endif

#if defined WITH_RAINHASH
// ----- v1 -----
template bool vole_reconstruct<v1::rainhash_then_mayo_128_s>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v1::rainhash_then_mayo_128_f>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
// ----- v2 -----
template bool vole_reconstruct<v2::rainhash_then_mayo_128_s>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
template bool vole_reconstruct<v2::rainhash_then_mayo_128_f>(block128, vole_block* __restrict__, const uint8_t*, const uint8_t* __restrict__, const uint8_t* __restrict__, uint8_t* __restrict__);
#endif


// clang-format on

} // namespace faest
