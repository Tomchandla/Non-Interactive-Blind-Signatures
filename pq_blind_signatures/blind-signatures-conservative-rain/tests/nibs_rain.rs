//! Integration tests for the mixed LowMC+MAYO(+Rain-for-t) NIBS scheme.
//!
//! Compiles as an EXTERNAL crate against the public API. Run with:
//!
//!     cargo test --test nibs_rain -- --nocapture
//!
//! Covers: derivation consistency (incl. the commitment opening), the
//! issue/MAYO half in isolation, a full round-trip per parameter set, the
//! public-m binding, and the reusability/unlinkability hooks (distinct
//! nonces / distinct recipients / distinct openings give distinct values).

use blind_signatures_conservative_rain::blind_sig_conservative_rain::{
    NibsLowmc, M_BYTES, PKR_BYTES,
};
use blind_signatures_conservative_rain::derive::{
    derive_com, derive_message, derive_pkr,
};
use blind_signatures_conservative_rain::zk::ZKType;

/// Every parameter set the scheme claims to support.
const PARAM_SETS: &[(&str, ZKType)] = &[
    ("FV1_128", ZKType::FV1_128),
    ("FV2_128", ZKType::FV2_128),
    ("SV1_128", ZKType::SV1_128),
    ("SV2_128", ZKType::SV2_128),
];

/// Build a fresh instance + both key pairs. Factored out so each test starts
/// from an identical, honestly-generated state.
fn fresh(
    zk: ZKType,
) -> (
    NibsLowmc,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    blind_signatures_conservative_rain::blind_sig_conservative_rain::RecipientSk,
) {
    let bs = NibsLowmc::setup(zk);
    let (pk, sk) = bs.keygen_signer();
    let (pk_r, sk_r) = bs.keygen_recipient();
    (bs, pk, sk, pk_r, sk_r)
}

/// The derived values (pkR, com, m) must have the fixed byte lengths the
/// circuit assumes, and derive_pkr(K, s) must reproduce the pk_r from
/// keygen_recipient. A mismatch here is the first thing that breaks the
/// (skR, nonce) -> m binding.
#[test]
fn witness_derivation_is_consistent() {
    let (bs, _pk, _sk, pk_r, sk_r) = fresh(ZKType::SV1_128);

    let derived_pk_r = derive_pkr(&sk_r.key, &sk_r.opening);
    assert_eq!(
        derived_pk_r, pk_r,
        "derive_pkr(sk_r) must equal the pk_r returned by keygen_recipient"
    );
    assert_eq!(derived_pk_r.len(), PKR_BYTES, "pkR must be {PKR_BYTES} bytes");

    let nonce = vec![0x07u8; 16];
    let com = derive_com(&derived_pk_r, &nonce);
    assert_eq!(
        com.len(),
        bs.mayo.mayo_params.m_digest_bytes,
        "com must be exactly the MAYO digest length"
    );

    let m = derive_message(&sk_r.key, &nonce);
    assert_eq!(m.len(), M_BYTES, "derived message m must be {M_BYTES} bytes");
}

/// The issued presignature must MAYO-verify against
/// com = MMO(pkR, PT(DOM_COM, nonce)) for the nonce Issue sampled. This
/// isolates the signer/issue half from the proving half.
#[test]
fn issued_presignature_verifies_as_mayo_signature() {
    let (bs, pk, sk, pk_r, _sk_r) = fresh(ZKType::SV1_128);

    let (presig, nonce) = bs.issue(&sk, &pk_r);
    let com = derive_com(&pk_r, &nonce);

    assert!(
        bs.mayo.verify_fixed_length_rain(&pk, &com, &presig),
        "the presignature the signer issued must verify against com"
    );
}

/// The headline property: a full honest run of the protocol produces a
/// signature that publicly verifies, across every parameter set.
#[test]
fn full_round_trip_verifies_all_param_sets() {
    for (name, zk) in PARAM_SETS {
        let (bs, pk, sk, pk_r, sk_r) = fresh(*zk);
        let mut epk = bs.mayo.expand_pk(&pk);
        let mut additional_r = [0xffu8; 32];

        let (presig, nonce) = bs.issue(&sk, &pk_r);
        let (m, mut sig) =
            bs.obtain(&pk, &mut epk, &sk_r, &presig, &nonce, &mut additional_r);

        assert!(
            bs.verify(&mut epk, &m, &mut sig, &mut additional_r),
            "[{name}] honest signature must verify"
        );
    }
}

/// Verification must be bound to the message: verifying a valid signature
/// against a DIFFERENT m has to fail. If this passes with a tampered m, the
/// public-output constraint on gadget GadM is not actually binding.
#[test]
fn verification_rejects_wrong_message() {
    let (bs, pk, sk, pk_r, sk_r) = fresh(ZKType::SV1_128);
    let mut epk = bs.mayo.expand_pk(&pk);
    let mut additional_r = [0xffu8; 32];

    let (presig, nonce) = bs.issue(&sk, &pk_r);
    let (m, mut sig) =
        bs.obtain(&pk, &mut epk, &sk_r, &presig, &nonce, &mut additional_r);

    let mut wrong_m = m.clone();
    wrong_m[0] ^= 0x01;

    assert!(
        !bs.verify(&mut epk, &wrong_m, &mut sig, &mut additional_r),
        "verification must reject a signature checked against the wrong message"
    );
    // and the untampered one still passes (guards against a verify that always fails)
    assert!(bs.verify(&mut epk, &m, &mut sig, &mut additional_r));
}

/// Reusability hook (BCGY24 Def. 5.2): two independent issuances for the SAME
/// recipient must yield distinct messages (the nonces differ w.o.p.).
#[test]
fn distinct_issuances_give_distinct_messages() {
    let (bs, pk, sk, pk_r, sk_r) = fresh(ZKType::SV1_128);
    let mut epk = bs.mayo.expand_pk(&pk);
    let mut additional_r = [0xffu8; 32];

    let (presig_a, nonce_a) = bs.issue(&sk, &pk_r);
    let (presig_b, nonce_b) = bs.issue(&sk, &pk_r);
    assert_ne!(nonce_a, nonce_b, "128-bit nonces must not collide in a test run");

    let (m_a, _) = bs.obtain(&pk, &mut epk, &sk_r, &presig_a, &nonce_a, &mut additional_r);
    let (m_b, _) = bs.obtain(&pk, &mut epk, &sk_r, &presig_b, &nonce_b, &mut additional_r);

    assert_ne!(m_a, m_b, "different nonces must derive different messages");
}

/// Distinct recipients must derive distinct messages for the SAME nonce
/// (pseudorandomness under independent keys).
#[test]
fn distinct_recipients_give_distinct_messages() {
    let (bs, _pk, _sk, _pk_r1, sk_r1) = fresh(ZKType::SV1_128);
    let (_pk_r2, sk_r2) = bs.keygen_recipient();

    let nonce = vec![0x07u8; 16];
    let m1 = derive_message(&sk_r1.key, &nonce);
    let m2 = derive_message(&sk_r2.key, &nonce);

    assert_ne!(m1, m2, "different recipients must derive different messages");
}

/// Commitment shape: same key, different openings -> different pkR
/// (the hiding hook for the Com(K; s) fidelity change).
#[test]
fn distinct_openings_give_distinct_pkr() {
    let (bs, _pk, _sk, _pk_r, sk_r) = fresh(ZKType::SV1_128);
    let mut other = sk_r.opening.clone();
    other[0] ^= 0x01;
    assert_ne!(
        derive_pkr(&sk_r.key, &sk_r.opening),
        derive_pkr(&sk_r.key, &other)
    );
    let _ = bs;
}
