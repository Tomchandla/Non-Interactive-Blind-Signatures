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

/*
TEST_CASE("volemayo prove v1_128_s", "[volemayo prove v1_128_s]")
{
    std::cout << "\nRunning volemayo prove v1_128_s\n";
    using P = faest::v1::mayo_128_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);



    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
*/

/*
TEST_CASE("volemayo prove v1_128_f", "[volemayo prove v1_128_f]")
{
    std::cout << "\nRunning volemayo prove v1_128_f\n";
    using P = faest::v1::mayo_128_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volemayo prove v2_128_s", "[volemayo prove v2_128_s]")
{
    std::cout << "\nRunning volemayo prove v2_128_s\n";
    using P = faest::v2::mayo_128_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volemayo prove v2_128_f", "[volemayo prove v2_128_f]")
{
    std::cout << "\nRunning volemayo prove v2_128_f\n";
    using P = faest::v2::mayo_128_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

TEST_CASE("volemayo prove v1_192_s", "[volemayo prove v1_192_s]")
{
    std::cout << "\nRunning volemayo prove v1_192_s\n";
    using P = faest::v1::mayo_192_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volemayo prove v1_192_f", "[volemayo prove v1_192_f]")
{
    std::cout << "\nRunning volemayo prove v1_192_f\n";
    using P = faest::v1::mayo_192_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volemayo prove v2_192_s", "[volemayo prove v2_192_s]")
{
    std::cout << "\nRunning volemayo prove v2_192_s\n";
    using P = faest::v2::mayo_192_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volemayo prove v2_192_f", "[volemayo prove v2_192_f]")
{
    std::cout << "\nRunning volemayo prove v2_192_f\n";
    using P = faest::v2::mayo_192_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

TEST_CASE("volemayo prove v1_256_s", "[volemayo prove v1_256_s]")
{
    std::cout << "\nRunning volemayo prove v1_256_s\n";
    using P = faest::v1::mayo_256_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volemayo prove v1_256_f", "[volemayo prove v1_256_f]")
{
    std::cout << "\nRunning volemayo prove v1_256_f\n";
    using P = faest::v1::mayo_256_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volemayo prove v2_256_s", "[volemayo prove v2_256_s]")
{
    std::cout << "\nRunning volemayo prove v2_256_s\n";
    using P = faest::v2::mayo_256_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volemayo prove v2_256_f", "[volemayo prove v2_256_f]")
{
    std::cout << "\nRunning volemayo prove v2_256_f\n";
    using P = faest::v2::mayo_256_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());
    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();
    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
*/


TEST_CASE("volemayo vole_prove v1_128_s", "[volemayo vole_prove v1_128_s]")
{
    std::cout << "\nRunning volemayo prove v1_128_s\n";
    using P = faest::v1::mayo_128_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);

    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
TEST_CASE("volemayo vole_prove v1_128_f", "[volemayo vole_prove v1_128_f]")
{
    std::cout << "\nRunning volemayo prove v1_128_f\n";
    using P = faest::v1::mayo_128_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);
    

    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());
    
    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
TEST_CASE("volemayo vole_prove v2_128_s", "[volemayo vole_prove v2_128_s]")
{
    std::cout << "\nRunning volemayo prove v2_128_s\n";
    using P = faest::v2::mayo_128_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);
    

    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());
    
    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
TEST_CASE("volemayo vole_prove v2_128_f", "[volemayo vole_prove v2_128_f]")
{
    std::cout << "\nRunning volemayo prove v12_128_f\n";
    using P = faest::v2::mayo_128_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);
    
    
    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}

TEST_CASE("volemayo vole_prove v1_192_s", "[volemayo vole_prove v1_192_s]")
{
    std::cout << "\nRunning volemayo vole_prove v1_192_s\n";
    using P = faest::v1::mayo_192_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);
    

    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}

TEST_CASE("volemayo vole_prove v1_192_f", "[volemayo vole_prove v1_192_f]")
{
    std::cout << "\nRunning volemayo vole_prove v1_192_f\n";
    using P = faest::v1::mayo_192_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);


    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
TEST_CASE("volemayo vole_prove v2_192_s", "[volemayo vole_prove v2_192_s]")
{
    std::cout << "\nRunning volemayo vole_prove v2_192_s\n";
    using P = faest::v2::mayo_192_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);


    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
TEST_CASE("volemayo vole_prove v2_192_f", "[volemayo vole_prove v2_192_f]")
{
    std::cout << "\nRunning volemayo vole_prove v2_192_f\n";
    using P = faest::v2::mayo_192_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);
   

    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}

TEST_CASE("volemayo vole_prove v1_256_s", "[volemayo vole_prove v1_256_s]")
{
    std::cout << "\nRunning volemayo vole_prove v1_256_s\n";
    using P = faest::v1::mayo_256_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);


    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
TEST_CASE("volemayo vole_prove v1_256_f", "[volemayo vole_prove v1_256_f]")
{
    std::cout << "\nRunning volemayo vole_prove v1_256_f\n";
    using P = faest::v1::mayo_256_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);


    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
TEST_CASE("volemayo vole_prove v2_256_s", "[volemayo vole_prove v2_256_s]")
{
    std::cout << "\nRunning volemayo vole_prove v2_256_s\n";
    using P = faest::v2::mayo_256_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);


    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
TEST_CASE("volemayo vole_prove v2_256_f", "[volemayo vole_prove v2_256_f]")
{
    std::cout << "\nRunning volemayo vole_prove v2_256_f\n";
    using P = faest::v2::mayo_256_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    std::vector<uint8_t> r(VOLEMAYO_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);


    vole_prove_1<P>(chal1.data(), r.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0, (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<P::secpar_v>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data(), r.data());

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, pk_packed.data(), sk_packed.data(), (uint8_t*)&r_additional);

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, pk_packed.data(), pk_packed.size(), (uint8_t*)&r_additional);

    REQUIRE(ret == true);

}
