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


TEST_CASE("volekeccak_then_mayo prove v1_128_s", "[volekeccak_then_mayo prove v1_128_s]")
{
    std::cout << "\nRunning volekeccak_then_mayo prove v1_128_s\n";
    using P = faest::v1::keccak_then_mayo_128_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLEKECCAK_SECRET_SIZE_BYTES<S>> sk_packed;

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

TEST_CASE("volekeccak_then_mayo vole_sig v1_128_s", "[volekeccak_then_mayo vole_sig v1_128_s]") {

    std::cout << "\nRunning volekeccak_then_mayo vole_sig v1_128_s\n";
    using P = faest::v1::keccak_then_mayo_128_s;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLEKECCAK_SECRET_SIZE_BYTES<S>> sk_packed;
    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), sk_packed.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), pk_packed.data()));

}

/*
TEST_CASE("volekeccak_then_mayo vole_prove v1_128_s", "[volekeccak_then_mayo vole_prove v1_128_s]")
{
    std::cout << "\nRunning volekeccak_then_mayo prove v1_128_s\n";
    using P = faest::v1::keccak_then_mayo_128_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLEKECCAK_SECRET_SIZE_BYTES<S>> sk_packed;

    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());

    public_key<P> pk;
    secret_key<P> sk;

    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    uint8_t* s = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_WITNESS_SIZE_BYTES<S>;
    uint8_t* rand = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
    #if defined KECCAK_DEG_16
    uint8_t* salt = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + RAND_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES * (VOLEKECCAK_NUM_ROUNDS/6) + VOLEMAYO_DIGEST_BYTES<P::secpar_v>;
    #else
    uint8_t* salt = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + RAND_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES * (VOLEKECCAK_NUM_ROUNDS) + VOLEMAYO_DIGEST_BYTES<P::secpar_v>;
    #endif

    vole_prove<P>(
        proof.data(), 
        NULL, 
        0, 
        (uint8_t*)&pk.pk_seed, 
        (uint8_t*)&pk.EPa_1, 
        (uint8_t*)&pk.EPa_2, 
        (uint8_t*)&pk.EPa_3, 
        (uint8_t*)&pk.cpk,
        (uint8_t*)&pk.msg, 
        s,
        rand,
        salt);     // For now setting random seed and random seed length to NULL and 0


    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, 
    (uint8_t*)&pk.pk_seed, 
    (uint8_t*)&pk.EPa_1, 
    (uint8_t*)&pk.EPa_2, 
    (uint8_t*)&pk.EPa_3, 
    (uint8_t*)&pk.cpk, 
    (uint8_t*)&pk.msg);


    REQUIRE(ret == true);

}*/

