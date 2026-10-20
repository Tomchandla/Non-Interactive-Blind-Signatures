// Circuit-level checks with the constraint evaluator (no proofs involved):
// the honest witness satisfies every constraint, and mismatched secrets or a
// single flipped witness bit do not.
//
//   RUST_MIN_STACK=8388608 cargo test --release --test soundness -- --nocapture
//   NIBS_SOUNDNESS_EXHAUSTIVE=1 ... flips every witness bit of BCGY+MAYO SV1_128

use ni_blind_signatures::zk::{count_unsatisfied, Witness};
use ni_blind_signatures::{Nibs, NibsParams, RecipientSk, ZKType};
use rand::Rng;

struct Fixture {
    bs: Nibs,
    epk: Vec<u8>,
    sk_r: RecipientSk,
    presig: Vec<u8>,
    nonce: Vec<u8>,
    m: Vec<u8>,
}

fn fixture(p: NibsParams) -> Fixture {
    let bs = Nibs::setup(p);
    let (pk, sk) = bs.keygen_signer();
    let epk = bs.expand_pk(&pk);
    let (pk_r, sk_r) = bs.keygen_recipient();
    let (presig, nonce) = bs.issue(&sk, &pk_r);
    let m = bs.derive_message(&sk_r.key, &nonce);
    Fixture { bs, epk, sk_r, presig, nonce, m }
}

fn unsat(f: &Fixture, key: &[u8], nonce: &[u8], m: &[u8], flip: Option<usize>) -> usize {
    let (s, salt) = f.presig.split_at(f.bs.info.s_bytes);
    let w = Witness { s, key, opening: &f.sk_r.opening, nonce, salt };
    count_unsatisfied(&f.bs.params, &f.epk, m, &w, flip).expect("valid instance")
}

#[test]
fn honest_witness_satisfies_every_instance() {
    for p in NibsParams::all() {
        let f = fixture(p);
        assert_eq!(unsat(&f, &f.sk_r.key, &f.nonce, &f.m, None), 0, "[{p}]");
    }
}

#[test]
fn mismatched_secrets_are_rejected() {
    for zk in [ZKType::SV1_128, ZKType::FV1_192, ZKType::FV1_256] {
        for p in NibsParams::variants(zk) {
            let f = fixture(p);
            // presignature issued to A, receiver key of B (with B's own message)
            let (_, sk_b) = f.bs.keygen_recipient();
            let m_b = f.bs.derive_message(&sk_b.key, &f.nonce);
            let wb = Witness {
                s: &f.presig[..f.bs.info.s_bytes],
                key: &sk_b.key,
                opening: &sk_b.opening,
                nonce: &f.nonce,
                salt: &f.presig[f.bs.info.s_bytes..],
            };
            let n = count_unsatisfied(&f.bs.params, &f.epk, &m_b, &wb, None).unwrap();
            assert!(n > 0, "[{p}] presignature of A accepted with the key of B");

            // the right key but another nonce (m recomputed for that nonce)
            let mut n2 = f.nonce.clone();
            n2[0] ^= 1;
            let m2 = f.bs.derive_message(&f.sk_r.key, &n2);
            assert!(unsat(&f, &f.sk_r.key, &n2, &m2, None) > 0, "[{p}] presignature moved to another nonce");

            // a public message that is not P_K(.) of the signed nonce
            let mut m3 = f.m.clone();
            m3[1] ^= 0x10;
            assert_eq!(unsat(&f, &f.sk_r.key, &f.nonce, &m3, None), 1, "[{p}] exactly one m bit differs");
        }
    }
}

#[test]
fn every_sampled_witness_bit_is_load_bearing() {
    let mut rng = rand::rng();
    for zk in [ZKType::SV1_128, ZKType::FV1_192, ZKType::FV1_256] {
        for p in NibsParams::variants(zk) {
            let f = fixture(p);
            let bits = f.bs.info.witness_bits;
            let mut idx: Vec<usize> = vec![0, bits - 1, f.bs.info.nibs_witness_bits - 1, f.bs.info.nibs_witness_bits];
            idx.extend((0..60).map(|_| rng.random_range(0..bits)));
            for b in idx {
                assert!(
                    unsat(&f, &f.sk_r.key, &f.nonce, &f.m, Some(b)) > 0,
                    "[{p}] flipping witness bit {b} left the relation satisfied"
                );
            }
        }
    }
}

#[test]
#[ignore]
fn exhaustive_bit_flips_level1() {
    if std::env::var("NIBS_SOUNDNESS_EXHAUSTIVE").is_err() {
        return;
    }
    for p in NibsParams::variants(ZKType::SV1_128) {
        let f = fixture(p);
        let bits = f.bs.info.witness_bits;
        for b in 0..bits {
            assert!(unsat(&f, &f.sk_r.key, &f.nonce, &f.m, Some(b)) > 0, "[{p}] bit {b}");
        }
        println!("[{p}] all {bits} witness bits are load-bearing");
    }
}
