#include <array>

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

// faest files
#include "faest_keys.hpp"
#include "owf_proof.hpp"
// #include "vole_proof/vole.cpp"
#include "faest.cpp"
#include "test.hpp"
#include <memory>

TEST_CASE("volerainhash prove v1_128s", "[volerainhash prove v1_128s]")
{
    using P = faest::v1::rainhash_128_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLERAINHASH_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());
    
    // faest_unpack_public_key<P>(&pk, packed_pk.data());
    faest_unpack_secret_key<P>(&sk, packed_sk.data());

    const auto delta = rand<faest::block_secpar<S>>();

    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;

    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    memcpy((uint8_t*)&rain_rc_qs<P>, (uint8_t*)&rain_roundconst, 64*7);
    memcpy((uint8_t*)&rain_mat_qs<P>, (uint8_t*)&rain_matrix, 64*512*7);

    // for (size_t state_idx = 0; state_idx < 24; state_idx++) {
    //     std::cout << "\n";
    //     std::cout << "rain_roundconst 111 val\n";
    //     std::cout << rain_roundconst[state_idx] << ", ";
    //     std::cout << "\n\n";
    // }

    owf_constraints<P, false>(&qs_state_prover, NULL);
    // owf_constraints<P, true>(&qs_state_verifier, &pk);

    // auto [check_prover, check_verifier] = qs_test.compute_check();
    // REQUIRE(check_prover == check_verifier);
}





// TEST_CASE("volerainhash prove v1_128f", "[volerainhash prove v1_128f]")
// {
//     using P = faest::v1::rainhash_128_f;
//     constexpr auto S = P::secpar_v;

//     public_key<P> pk;
//     secret_key<P> sk;

//     std::array<uint8_t, faest::VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
//     std::array<uint8_t, faest::VOLERAINHASH_SECRET_SIZE_BYTES> packed_sk;

//     test_gen_keypair<P>(packed_pk.data(), packed_sk.data());
    
//     faest_unpack_public_key<P>(&pk, packed_pk.data());
//     faest_unpack_secret_key<P>(&sk, packed_sk.data());

//     const auto delta = rand<faest::block_secpar<S>>();

//     quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
//                                         reinterpret_cast<uint8_t*>(sk.witness),
//                                         P::OWF_CONSTS::WITNESS_BITS, delta);

//     auto& qs_state_prover = qs_test.prover_state;
//     auto& qs_state_verifier = qs_test.verifier_state;

//     assert(&qs_state_verifier != nullptr);
//     assert(&pk != nullptr);

//     owf_constraints<P, false>(&qs_state_prover, &sk.pk);
//     owf_constraints<P, true>(&qs_state_verifier, &pk);

//     auto [check_prover, check_verifier] = qs_test.compute_check();
//     REQUIRE(check_prover == check_verifier);
// }

// TEST_CASE("volerainhash prove v2_128s", "[volerainhash prove v2_128s]")
// {
//     using P = faest::v2::rainhash_128_s;
//     constexpr auto S = P::secpar_v;

//     public_key<P> pk;
//     secret_key<P> sk;

//     std::array<uint8_t, faest::VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
//     std::array<uint8_t, faest::VOLERAINHASH_SECRET_SIZE_BYTES> packed_sk;

//     test_gen_keypair<P>(packed_pk.data(), packed_sk.data());
    
//     faest_unpack_public_key<P>(&pk, packed_pk.data());
//     faest_unpack_secret_key<P>(&sk, packed_sk.data());

//     const auto delta = rand<faest::block_secpar<S>>();

//     quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
//                                         reinterpret_cast<uint8_t*>(sk.witness),
//                                         P::OWF_CONSTS::WITNESS_BITS, delta);

//     auto& qs_state_prover = qs_test.prover_state;
//     auto& qs_state_verifier = qs_test.verifier_state;

//     assert(&qs_state_verifier != nullptr);
//     assert(&pk != nullptr);

//     owf_constraints<P, false>(&qs_state_prover, &sk.pk);
//     owf_constraints<P, true>(&qs_state_verifier, &pk);

//     auto [check_prover, check_verifier] = qs_test.compute_check();
//     REQUIRE(check_prover == check_verifier);
// }
// TEST_CASE("volerainhash prove v2_128f", "[volerainhash prove v2_128f]")
// {
//     using P = faest::v2::rainhash_128_f;
//     constexpr auto S = P::secpar_v;

//     public_key<P> pk;
//     secret_key<P> sk;

//     std::array<uint8_t, faest::VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
//     std::array<uint8_t, faest::VOLERAINHASH_SECRET_SIZE_BYTES> packed_sk;

//     test_gen_keypair<P>(packed_pk.data(), packed_sk.data());
    
//     faest_unpack_public_key<P>(&pk, packed_pk.data());
//     faest_unpack_secret_key<P>(&sk, packed_sk.data());

//     const auto delta = rand<faest::block_secpar<S>>();

//     quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
//                                         reinterpret_cast<uint8_t*>(sk.witness),
//                                         P::OWF_CONSTS::WITNESS_BITS, delta);

//     auto& qs_state_prover = qs_test.prover_state;
//     auto& qs_state_verifier = qs_test.verifier_state;

//     assert(&qs_state_verifier != nullptr);
//     assert(&pk != nullptr);

//     owf_constraints<P, false>(&qs_state_prover, &sk.pk);
//     owf_constraints<P, true>(&qs_state_verifier, &pk);

//     auto [check_prover, check_verifier] = qs_test.compute_check();
//     REQUIRE(check_prover == check_verifier);
// }

// TEST_CASE("volerainhash vole_prove v1_128s", "[volerainhash vole_prove v1_128s]")
// {

//     using P = faest::v1::rainhash_128_s;
//     using CP = P::CONSTS;
//     constexpr auto S = P::secpar_v;

//     std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
//     faest::block128 iv_out;
//     faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
//     faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
//     faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
//     unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
//     std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
//     uint8_t* commit_mu = new uint8_t[VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>];
//     memset(commit_mu, 0x00, VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>);


//     std::array<uint8_t, faest::VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
//     std::array<uint8_t, faest::VOLERAINHASH_SECRET_SIZE_BYTES> packed_sk;
//     test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

//     vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, (uint8_t*)&proof, commit_mu, VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>);

//     vole_prove_2<P>(proof.data(), (uint8_t*)&chal1, u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

//     bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

//     // TODO: of course this should be true!
//     REQUIRE(ret == false);

// }
// TEST_CASE("volerainhash vole_prove v1_128f", "[volerainhash vole_prove v1_128f]")
// {

//     using P = faest::v1::rainhash_128_f;
//     using CP = P::CONSTS;
//     constexpr auto S = P::secpar_v;

//     std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
//     faest::block128 iv_out;
//     faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
//     faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
//     faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
//     unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
//     std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
//     uint8_t* commit_mu = new uint8_t[VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>];
//     memset(commit_mu, 0x00, VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>);


//     std::array<uint8_t, faest::VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
//     std::array<uint8_t, faest::VOLERAINHASH_SECRET_SIZE_BYTES> packed_sk;
//     test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

//     vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, (uint8_t*)&proof, commit_mu, VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>);

//     vole_prove_2<P>(proof.data(), (uint8_t*)&chal1, u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

//     bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

//     // TODO: of course this should be true!
//     REQUIRE(ret == false);

// }

// TEST_CASE("volerainhash vole_prove v2_128s", "[volerainhash vole_prove v2_128s]")
// {

//     using P = faest::v2::rainhash_128_s;
//     using CP = P::CONSTS;
//     constexpr auto S = P::secpar_v;

//     std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
//     faest::block128 iv_out;
//     faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
//     faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
//     faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
//     unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
//     std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
//     uint8_t* commit_mu = new uint8_t[VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>];
//     memset(commit_mu, 0x00, VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>);


//     std::array<uint8_t, faest::VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
//     std::array<uint8_t, faest::VOLERAINHASH_SECRET_SIZE_BYTES> packed_sk;
//     test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

//     vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, (uint8_t*)&proof, commit_mu, VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>);

//     vole_prove_2<P>(proof.data(), (uint8_t*)&chal1, u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

//     bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

//     // TODO: of course this should be true!
//     REQUIRE(ret == false);

// }
// TEST_CASE("volerainhash vole_prove v2_128f", "[volerainhash vole_prove v2_128f]")
// {

//     using P = faest::v2::rainhash_128_f;
//     using CP = P::CONSTS;
//     constexpr auto S = P::secpar_v;

//     std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
//     faest::block128 iv_out;
//     faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
//     faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
//     faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
//     unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
//     std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
//     uint8_t* commit_mu = new uint8_t[VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>];
//     memset(commit_mu, 0x00, VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>);


//     std::array<uint8_t, faest::VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
//     std::array<uint8_t, faest::VOLERAINHASH_SECRET_SIZE_BYTES> packed_sk;
//     test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

//     vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, (uint8_t*)&proof, commit_mu, VOLERAINHASH_COMMIT_MU_SIZE_BYTES<S>);

//     vole_prove_2<P>(proof.data(), (uint8_t*)&chal1, u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

//     bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

//     // TODO: of course this should be true!
//     REQUIRE(ret == false);

// }

