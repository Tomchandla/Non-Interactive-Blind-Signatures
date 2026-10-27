// Integration tests for both NIBS frameworks at every NIST level.
//
//   RUST_MIN_STACK=8388608 cargo test --release --test nibs
//
// Set NIBS_TEST_ALL=1 to run the full 24-instance round trip (s/f x v1/v2);
// by default both frameworks and every level are covered with one VOLEitH
// set each, and every VOLEitH set is covered for level 1.

use ni_blind_signatures::{Framework, Nibs, NibsParams, Signature, ZKType};

fn instances() -> Vec<NibsParams> {
    if std::env::var("NIBS_TEST_ALL").is_ok() {
        return NibsParams::all();
    }
    let mut v = Vec::new();
    for zk in [ZKType::SV1_128, ZKType::SV2_128, ZKType::FV1_128, ZKType::FV2_128] {
        v.extend(NibsParams::variants(zk));
    }
    for zk in [ZKType::FV2_192, ZKType::FV2_256] {
        v.extend(NibsParams::variants(zk));
    }
    v
}

struct Session {
    bs: Nibs,
    pk: Vec<u8>,
    sk: Vec<u8>,
    epk: Vec<u8>,
}

fn session(p: NibsParams) -> Session {
    let bs = Nibs::setup(p);
    let (pk, sk) = bs.keygen_signer();
    let epk = bs.expand_pk(&pk);
    Session { bs, pk, sk, epk }
}

#[test]
fn round_trip_every_variant_and_level() {
    for p in instances() {
        let s = session(p);
        let (pk_r, sk_r) = s.bs.keygen_recipient();
        let (presig, nonce) = s.bs.issue(&s.sk, &pk_r);
        assert_eq!(presig.len(), s.bs.presignature_bytes(), "[{p}] presignature size");
        let (m, sig) = s.bs.obtain(&s.pk, &s.epk, &sk_r, &presig, &nonce).expect("valid presig");
        assert_eq!(sig.proof.len(), s.bs.signature_bytes());
        assert!(s.bs.verify(&s.pk, &s.epk, &m, &sig), "[{p}] honest signature must verify");
        println!(
            "[{p}] |presig| = {} B, |sigma| = {} B, witness = {} bits ({} NIBS + {} MAYO), {} constraints",
            presig.len(),
            sig.proof.len(),
            s.bs.info.witness_bits,
            s.bs.info.nibs_witness_bits,
            s.bs.info.mayo_s_bits,
            s.bs.info.constraints
        );
    }
}

#[test]
fn verification_rejects_modified_statement_or_proof() {
    for zk in [ZKType::SV1_128, ZKType::FV2_192, ZKType::FV2_256] {
        for p in NibsParams::variants(zk) {
            let s = session(p);
            let (pk_r, sk_r) = s.bs.keygen_recipient();
            let (presig, nonce) = s.bs.issue(&s.sk, &pk_r);
            let (m, sig) = s.bs.obtain(&s.pk, &s.epk, &sk_r, &presig, &nonce).unwrap();

            let mut wrong_m = m.clone();
            wrong_m[0] ^= 1;
            assert!(!s.bs.verify(&s.pk, &s.epk, &wrong_m, &sig), "[{p}] wrong m accepted");

            let (pk2, _) = s.bs.keygen_signer();
            let epk2 = s.bs.expand_pk(&pk2);
            assert!(!s.bs.verify(&pk2, &epk2, &m, &sig), "[{p}] other signer key accepted");

            for pos in [0, sig.proof.len() / 2, sig.proof.len() - 20] {
                let mut bad = sig.clone();
                bad.proof[pos] ^= 0x01;
                assert!(!s.bs.verify(&s.pk, &s.epk, &m, &bad), "[{p}] tampered proof accepted");
            }

            // a valid proof for one instance is not valid for another one
            for q in NibsParams::variants(zk) {
                if q != p {
                    let other = Nibs::setup(q);
                    if other.signature_bytes() == sig.proof.len() {
                        assert!(!other.verify(&s.pk, &s.epk, &m, &sig), "[{p}] accepted as {q}");
                    }
                }
            }
        }
    }
}

#[test]
fn obtain_rejects_foreign_or_altered_presignatures() {
    for p in NibsParams::variants(ZKType::FV1_128) {
        let s = session(p);
        let (pk_a, sk_a) = s.bs.keygen_recipient();
        let (_pk_b, sk_b) = s.bs.keygen_recipient();
        let (presig, nonce) = s.bs.issue(&s.sk, &pk_a);

        // issued to A, so B cannot use it
        assert!(s.bs.obtain(&s.pk, &s.epk, &sk_b, &presig, &nonce).is_none(), "[{p}]");
        let mut n2 = nonce.clone();
        n2[0] ^= 1;
        assert!(s.bs.obtain(&s.pk, &s.epk, &sk_a, &presig, &n2).is_none(), "[{p}]");
        let mut ps2 = presig.clone();
        ps2[3] ^= 1;
        assert!(s.bs.obtain(&s.pk, &s.epk, &sk_a, &ps2, &nonce).is_none(), "[{p}]");
    }
}

#[test]
fn messages_are_fresh_per_nonce_and_per_receiver() {
    for p in NibsParams::variants(ZKType::FV1_128) {
        let s = session(p);
        let (pk_r, sk_r) = s.bs.keygen_recipient();
        let (_, sk_r2) = s.bs.keygen_recipient();
        let (ps1, n1) = s.bs.issue(&s.sk, &pk_r);
        let (ps2, n2) = s.bs.issue(&s.sk, &pk_r);
        assert_ne!(n1, n2);
        let (m1, _) = s.bs.obtain(&s.pk, &s.epk, &sk_r, &ps1, &n1).unwrap();
        let (m2, _) = s.bs.obtain(&s.pk, &s.epk, &sk_r, &ps2, &n2).unwrap();
        assert_ne!(m1, m2, "[{p}] different nonces must give different messages");
        assert_ne!(
            s.bs.derive_message(&sk_r.key, &n1),
            s.bs.derive_message(&sk_r2.key, &n1),
            "[{p}] different receivers must give different messages"
        );
    }
}

// Regression test for the constant VOLE seed of the previous implementation:
// proofs from different receivers shared their whole VOLE commitment and the
// witness correction d = u ^ w exposed w1 ^ w2.
#[test]
fn proofs_use_fresh_vole_randomness() {
    for p in [
        NibsParams::new(Framework::Bcgy, ZKType::SV1_128),
        NibsParams::new(Framework::Sprp, ZKType::FV2_192),
    ] {
        let s = session(p);
        assert_eq!(s.bs.info.random_seed_bytes * 8, p.zk.lambda());
        let (pk_a, sk_a) = s.bs.keygen_recipient();
        let (pk_b, sk_b) = s.bs.keygen_recipient();
        let (ps_a, n_a) = s.bs.issue(&s.sk, &pk_a);
        let (ps_b, n_b) = s.bs.issue(&s.sk, &pk_b);
        let (_, sa) = s.bs.obtain(&s.pk, &s.epk, &sk_a, &ps_a, &n_a).unwrap();
        let (_, sa2) = s.bs.obtain(&s.pk, &s.epk, &sk_a, &ps_a, &n_a).unwrap();
        let (_, sb) = s.bs.obtain(&s.pk, &s.epk, &sk_b, &ps_b, &n_b).unwrap();
        let common = |x: &Signature, y: &Signature| {
            x.proof.iter().zip(&y.proof).take_while(|(a, b)| a == b).count()
        };
        assert!(common(&sa, &sb) < 8, "[{p}] proofs of different receivers share a prefix");
        assert!(common(&sa, &sa2) < 8, "[{p}] re-proving the same witness reuses randomness");
        // no 16-byte window of sa ^ sb equals K_a ^ K_b
        let kx: Vec<u8> = sk_a.key.iter().zip(&sk_b.key).map(|(x, y)| x ^ y).take(16).collect();
        let hit = (0..sa.proof.len() - 16)
            .any(|o| (0..16).all(|i| sa.proof[o + i] ^ sb.proof[o + i] == kx[i]));
        assert!(!hit, "[{p}] K_a ^ K_b visible in sigma_a ^ sigma_b");
    }
}

#[test]
fn reported_sizes_match_the_layout() {
    for p in NibsParams::all() {
        let bs = Nibs::setup(p);
        let i = &bs.info;
        let lb = p.zk.lambda() / 8;
        assert_eq!(i.k_bytes, lb);
        assert_eq!(i.r_bytes, lb);
        assert_eq!(i.m_bytes, lb);
        assert_eq!(i.pkr_bytes, if p.is_sprp() { lb } else { 2 * lb });
        assert_eq!(i.op_bytes, lb);
        assert_eq!(i.salt_bytes, bs.mayo.mayo_params.salt_bytes);
        assert_eq!(bs.presignature_bytes(), i.s_bytes + i.salt_bytes);
        assert_eq!(i.witness_bits, i.nibs_witness_bits + i.mayo_s_bits);
        assert_eq!(i.lowmc_gadgets, if p.is_sprp() { 2 } else { 1 });
        assert_eq!(i.rain_gadgets, i.target_blocks + if p.is_sprp() { 0 } else { 1 });
    }
}

/// The MAYO message is M = r || pk_R in both frameworks, so the nonce lies
/// entirely in the first Rain block of the target hash and the receiver
/// cannot precompute any chaining value. (With pk_R first, the 2 lambda-bit
/// BCGY pk_R fills the whole first block at level 5 and two target chains
/// could be merged by a 2^{(lambda+64)/2} birthday search run before asking
/// for a presignature.)
#[test]
fn presignature_message_puts_the_nonce_in_the_first_rain_block() {
    for zk in [ZKType::FV1_128, ZKType::FV1_192, ZKType::FV1_256] {
        for p in NibsParams::variants(zk) {
            let bs = Nibs::setup(p);
            let (pk_r, _) = bs.keygen_recipient();
            let nonce: Vec<u8> = (0..bs.info.r_bytes as u8).collect();
            let msg = bs.presig_message(&pk_r, &nonce);
            assert_eq!(msg, [nonce.as_slice(), pk_r.as_slice()].concat(), "[{p}]");
            let end = msg.windows(nonce.len()).position(|w| w == nonce.as_slice()).unwrap() + nonce.len();
            assert!(end <= 64, "[{p}] nonce ends at byte {end}, past the first Rain block");
        }
    }
}
