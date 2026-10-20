// LowMC as a strong PRP, and the key-binding question of the sPRP framework.
//
//   RUST_MIN_STACK=8388608 cargo test --release --test sprp -- --nocapture

use ni_blind_signatures::{Framework, MayoMode, Nibs, NibsParams, ZKType};
use rand::Rng;
use vole_rainhash_then_mayo_sys::lowmc;

fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..n).map(|_| rng.random()).collect()
}

/// E_K is a permutation of {0,1}^n for every K and E_K^{-1} is efficient:
/// both oracles of the sPRP game exist.
#[test]
fn lowmc_is_an_invertible_keyed_permutation() {
    lowmc::init();
    for level in [1u32, 3, 5] {
        let n = lowmc::block_bytes(level);
        assert_eq!(lowmc::rounds(level), 13);
        for _ in 0..200 {
            let k = random_bytes(n);
            let x = random_bytes(n);
            let y = lowmc::encrypt(level, &k, &x);
            assert_eq!(lowmc::decrypt(level, &k, &y), x);
            assert_eq!(lowmc::encrypt(level, &k, &lowmc::decrypt(level, &k, &x)), x);
        }
    }
}

/// The receiver key and message derivations of the implemented sPRP
/// instantiation, recomputed from raw LowMC calls.
#[test]
fn sprp_derivations_match_the_specification() {
    for zk in [ZKType::FV1_128, ZKType::FV1_192, ZKType::FV1_256] {
        let bs = Nibs::setup(NibsParams::new(Framework::Sprp, MayoMode::Standard, zk));
        let level = zk.level();
        let n = lowmc::block_bytes(level);
        let (pk_r, sk_r) = bs.keygen_recipient();
        assert!(sk_r.opening.is_empty());

        let c0 = vec![0u8; n];
        let mut c1 = vec![0u8; n];
        c1[0] = 1;
        let expect = [lowmc::encrypt(level, &sk_r.key, &c0), lowmc::encrypt(level, &sk_r.key, &c1)].concat();
        assert_eq!(pk_r, expect, "pk_R = P_K(0||c0) || P_K(0||c1)");

        let r = random_bytes(n);
        let mut pt = r.clone();
        *pt.last_mut().unwrap() |= 0x80; // domain bit 1 for messages
        assert_eq!(bs.derive_message(&sk_r.key, &r), lowmc::encrypt(level, &sk_r.key, &pt));
        // and the domain bit separates messages from pk_R inputs: the signer
        // cannot steer m onto either half of pk_R by choosing r = c0 or c1
        assert_ne!(bs.derive_message(&sk_r.key, &c0), expect[..n].to_vec());
        assert_ne!(bs.derive_message(&sk_r.key, &c1), expect[n..].to_vec());
    }
}

/// Definition 4.4 (key binding) asks that no adversary finds
/// (K, s) != (K', s') with P_K(0||s) = P_K'(0||s'). For any keyed
/// permutation whose inverse is efficient given the key -- which is exactly
/// what a strong PRP provides -- this fails: pick K' and decrypt.
///
/// In Algorithm 1 this yields a one-more forgery: one presignature on
/// r || pk_R verifies for every opening (K', s') of pk_R, and each opening
/// gives a different message m' = P_K'(1||r).
#[test]
fn definition_4_4_key_binding_fails_for_any_invertible_permutation() {
    lowmc::init();
    let level = 1;
    let n = lowmc::block_bytes(level);
    let k = random_bytes(n);
    let mut s = random_bytes(n);
    *s.last_mut().unwrap() &= 0x7f; // input 0||s
    let pk_r = lowmc::encrypt(level, &k, &s);

    let mut openings = Vec::new();
    let mut tries = 0;
    while openings.len() < 8 {
        tries += 1;
        let k2 = random_bytes(n);
        let x = lowmc::decrypt(level, &k2, &pk_r);
        if x.last().unwrap() & 0x80 == 0 {
            // x = 0||s' : (K', s') opens the same pk_R
            assert_eq!(lowmc::encrypt(level, &k2, &x), pk_r);
            openings.push((k2, x));
        }
    }
    println!("found {} second openings of pk_R = P_K(0||s) in {} tries", openings.len(), tries);
    let r = random_bytes(n);
    let mut pt = r.clone();
    *pt.last_mut().unwrap() |= 0x80;
    let msgs: std::collections::HashSet<Vec<u8>> =
        openings.iter().map(|(k2, _)| lowmc::encrypt(level, k2, &pt)).collect();
    assert_eq!(msgs.len(), openings.len(), "each opening derives a distinct message");
}
