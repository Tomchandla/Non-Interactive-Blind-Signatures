// LowMC as a strong PRP.

use ni_blind_signatures::{Framework, Nibs, NibsParams, ZKType};
use rand::Rng;
use vole_rainhash_then_mayo_sys::lowmc;

fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..n).map(|_| rng.random()).collect()
}

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

#[test]
fn sprp_derivations_match() {
    for zk in [ZKType::FV1_128, ZKType::FV1_192, ZKType::FV1_256] {
        let bs = Nibs::setup(NibsParams::new(Framework::Sprp, zk));
        let level = zk.level();
        let n = lowmc::block_bytes(level);
        let (pk_r, sk_r) = bs.keygen_recipient();
        let s = &sk_r.opening;
        assert_eq!(s.len(), n);
        assert_eq!(s.last().unwrap() & 0xc0, 0, "s in {{0,1}}^(n-2): domain bits 00");
        let mut s01 = s.clone();
        *s01.last_mut().unwrap() |= 0x40;
        let expected = [lowmc::encrypt(level, &sk_r.key, s), lowmc::encrypt(level, &sk_r.key, &s01)].concat();
        assert_eq!(pk_r, expected, "pk_R = P_K(00||s) || P_K(01||s)");

        let r = random_bytes(n);
        let mut pt = r.clone();
        *pt.last_mut().unwrap() |= 0x80; // domain bit 1 for messages
        assert_eq!(bs.derive_message(&sk_r.key, &r), lowmc::encrypt(level, &sk_r.key, &pt));
        // the domain bits separate messages from the pk_R inputs: choosing
        // r = s does not make m equal to either pk_R block
        let m_s = bs.derive_message(&sk_r.key, s);
        assert_ne!(m_s.as_slice(), &pk_r[..n]);
        assert_ne!(m_s.as_slice(), &pk_r[n..]);
        assert_eq!(bs.presig_message(&pk_r, &r), [r.as_slice(), pk_r.as_slice()].concat());

        // the signer's nonce is a (n-1)-bit value: top bit 0
        let (_, sk) = bs.keygen_signer();
        for _ in 0..16 {
            let (_, nonce) = bs.issue(&sk, &pk_r);
            assert_eq!(nonce.len(), n);
            assert_eq!(nonce.last().unwrap() & 0x80, 0, "r in {{0,1}}^(n-1)");
        }
    }
}

/// Why pk_R has two blocks: a single block P_K(0||s) is opened under any
/// other key K' by inverting, s' = P_{K'}^{-1}(pk_R), whenever the top bit of
/// s' is 0 (probability 1/2). That second opening turns one presignature into
/// two messages.
#[test]
fn single_block_pkr_is_not_key_binding() {
    lowmc::init();
    let level = 1;
    let n = lowmc::block_bytes(level);
    let k = random_bytes(n);
    let mut s = random_bytes(n);
    *s.last_mut().unwrap() &= 0x7f; // input 0||s
    let pk_r = lowmc::encrypt(level, &k, &s);

    let mut openings = Vec::new();
    while openings.len() < 8 {
        let k2 = random_bytes(n);
        let x = lowmc::decrypt(level, &k2, &pk_r);
        if x.last().unwrap() & 0x80 == 0 {
            assert_eq!(lowmc::encrypt(level, &k2, &x), pk_r);
            openings.push(k2);
        }
    }
    let mut pt = random_bytes(n);
    *pt.last_mut().unwrap() |= 0x80;
    let msgs: std::collections::HashSet<Vec<u8>> =
        openings.iter().map(|k2| lowmc::encrypt(level, k2, &pt)).collect();
    assert_eq!(msgs.len(), openings.len(), "each opening derives a distinct message");
}

/// The same inversion against the two-block pk_R: a key K' fixes s' from the
/// first block, and the second block then matches only with probability
/// 2^{-lambda}.
#[test]
fn inverting_one_block_does_not_open_the_two_block_pkr() {
    let bs = Nibs::setup(NibsParams::new(Framework::Sprp, ZKType::FV1_128));
    let level = 1;
    let n = lowmc::block_bytes(level);
    let (pk_r, _) = bs.keygen_recipient();
    let (lo, hi) = pk_r.split_at(n);
    let mut tried = 0;
    for _ in 0..1000 {
        let k2 = random_bytes(n);
        let mut x = lowmc::decrypt(level, &k2, lo);
        if x.last().unwrap() & 0xc0 != 0 {
            continue; // not of the form 00||s'
        }
        tried += 1;
        *x.last_mut().unwrap() |= 0x40;
        assert_ne!(lowmc::encrypt(level, &k2, &x).as_slice(), hi, "second block matched");
    }
    assert!(tried > 0);
}