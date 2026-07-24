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


TEST_CASE("volekeccak prove v1_128_s", "[volekeccak prove v1_128_s]")
{
    using P = faest::v1::keccak_128_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, NULL);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volekeccak prove v1_192_s", "[volekeccak prove v1_192_s]")
{
    using P = faest::v1::keccak_192_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volekeccak prove v1_256_s", "[volekeccak prove v1_256_s]")
{
    using P = faest::v1::keccak_256_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

TEST_CASE("volekeccak prove v2_128_s", "[volekeccak prove v2_128_s]")
{
    using P = faest::v2::keccak_128_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, NULL);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volekeccak prove v2_192_s", "[volekeccak prove v2_192_s]")
{
    using P = faest::v2::keccak_192_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volekeccak prove v2_256_s", "[volekeccak prove v2_256_s]")
{
    using P = faest::v2::keccak_256_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

TEST_CASE("volekeccak prove v1_128_f", "[volekeccak prove v1_128_f]")
{
    using P = faest::v1::keccak_128_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, NULL);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volekeccak prove v1_192_f", "[volekeccak prove v1_192_f]")
{
    using P = faest::v1::keccak_192_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volekeccak prove v1_256_f", "[volekeccak prove v1_256_f]")
{
    using P = faest::v1::keccak_256_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}

TEST_CASE("volekeccak prove v2_128_f", "[volekeccak prove v2_128_f]")
{
    using P = faest::v2::keccak_128_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, NULL);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volekeccak prove v2_192_f", "[volekeccak prove v2_192_f]")
{
    using P = faest::v2::keccak_192_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}
TEST_CASE("volekeccak prove v2_256_f", "[volekeccak prove v2_256_f]")
{
    using P = faest::v2::keccak_256_f;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

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

    owf_constraints<P, false>(&qs_state_prover, NULL);
    owf_constraints<P, true>(&qs_state_verifier, &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);
}



TEST_CASE("volekeccak vole_sig v1_128_s", "[volekeccak vole_sig v1_128_s]") {

    using P = faest::v1::keccak_128_s;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}
TEST_CASE("volekeccak vole_sig v1_192_s", "[volekeccak vole_sig v1_192_s]") {

    using P = faest::v1::keccak_192_s;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}
TEST_CASE("volekeccak vole_sig v1_256_s", "[volekeccak vole_sig v1_256_s]") {

    using P = faest::v1::keccak_256_s;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}

TEST_CASE("volekeccak vole_sig v2_128_s", "[volekeccak vole_sig v2_128_s]") {

    using P = faest::v2::keccak_128_s;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}
TEST_CASE("volekeccak vole_sig v2_192_s", "[volekeccak vole_sig v2_192_s]") {

    using P = faest::v2::keccak_192_s;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}
TEST_CASE("volekeccak vole_sig v2_256_s", "[volekeccak vole_sig v2_256_s]") {

    using P = faest::v2::keccak_256_s;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}

TEST_CASE("volekeccak vole_sig v1_128_f", "[volekeccak vole_sig v1_128_f]") {

    using P = faest::v1::keccak_128_f;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}
TEST_CASE("volekeccak vole_sig v1_192_f", "[volekeccak vole_sig v1_192_f]") {

    using P = faest::v1::keccak_192_f;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}
TEST_CASE("volekeccak vole_sig v1_256_f", "[volekeccak vole_sig v1_256_f]") {

    using P = faest::v1::keccak_256_f;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}

TEST_CASE("volekeccak vole_sig v2_128_f", "[volekeccak vole_sig v2_128_f]") {

    using P = faest::v2::keccak_128_f;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}
TEST_CASE("volekeccak vole_sig v2_192_f", "[volekeccak vole_sig v2_192_f]") {

    using P = faest::v2::keccak_192_f;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}
TEST_CASE("volekeccak vole_sig v2_256_f", "[volekeccak vole_sig v2_256_f]") {

    using P = faest::v2::keccak_256_f;
    constexpr auto S = P::secpar_v;

    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    std::vector<uint8_t> signature((int)faest::VOLE_PROOF_BYTES<P>);         
    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    const std::string message =
        "This document describes and specifies the FAEST digital signature algorithm.";

    REQUIRE(faest_sign<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                          message.size(), packed_sk.data(), NULL, 0));
    REQUIRE(faest_verify<P>(signature.data(), reinterpret_cast<const uint8_t*>(message.c_str()),
                            message.size(), packed_pk.data()));

}



TEST_CASE("volekeccak vole_prove v1_128_s", "[volekeccak vole_prove v1_128_s]")
{
    using P = faest::v1::keccak_128_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}
TEST_CASE("volekeccak vole_prove v1_192_s", "[volekeccak vole_prove v1_192_s]")
{
    using P = faest::v1::keccak_192_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}
TEST_CASE("volekeccak vole_prove v1_256_s", "[volekeccak vole_prove v1_256_s]")
{
    using P = faest::v1::keccak_256_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}

TEST_CASE("volekeccak vole_prove v2_128_s", "[volekeccak vole_prove v2_128_s]")
{
    using P = faest::v2::keccak_128_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}
TEST_CASE("volekeccak vole_prove v2_192_s", "[volekeccak vole_prove v2_192_s]")
{
    using P = faest::v2::keccak_192_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}
TEST_CASE("volekeccak vole_prove v2_256_s", "[volekeccak vole_prove v2_256_s]")
{
    using P = faest::v2::keccak_256_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}

TEST_CASE("volekeccak vole_prove v1_128_f", "[volekeccak vole_prove v1_128_f]")
{
    using P = faest::v1::keccak_128_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}
TEST_CASE("volekeccak vole_prove v1_192_f", "[volekeccak vole_prove v1_192_f]")
{
    using P = faest::v1::keccak_192_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}
TEST_CASE("volekeccak vole_prove v1_256_f", "[volekeccak vole_prove v1_256_f]")
{
    using P = faest::v1::keccak_256_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}

TEST_CASE("volekeccak vole_prove v2_128_f", "[volekeccak vole_prove v2_128_f]")
{
    using P = faest::v2::keccak_128_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}
TEST_CASE("volekeccak vole_prove v2_192_f", "[volekeccak vole_prove v2_192_f]")
{
    using P = faest::v2::keccak_192_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}
TEST_CASE("volekeccak vole_prove v2_256_f", "[volekeccak vole_prove v2_256_f]")
{
    using P = faest::v2::keccak_256_f;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> chal1(CP::VOLE_CHECK::CHALLENGE_BYTES);
    // std::vector<uint8_t> r(VOLEKECCAK_R_BYTES<S>);
    faest::block128 iv_out;
    faest::vole_block* u = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::vole_block* v = reinterpret_cast<faest::vole_block*>(aligned_alloc(alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    faest::block_secpar<P::secpar_v>* forest = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(alignof(faest::block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(faest::block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(alignof(faest::block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    
    
    // uint8_t proof[VOLE_PROOF_BYTES<P>];
    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    
    std::array<uint8_t, faest::VOLEKECCAK_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEKECCAK_SECRET_SIZE_BYTES> packed_sk;

    test_gen_keypair<P>(packed_pk.data(), packed_sk.data());

    vole_prove_1<P>(chal1.data(), u, v, forest, &iv_out, hashed_leaves, proof.data(), NULL, 0);     // For now setting random seed and random seed length to NULL and 0

    vole_prove_2<P>(proof.data(), chal1.data(), u, v, &iv_out, sizeof(iv_out), forest, hashed_leaves, packed_sk.data());

    bool ret = vole_verify<P>(proof.data(), VOLE_PROOF_BYTES<P>, packed_pk.data());

    REQUIRE(ret == true);

}

