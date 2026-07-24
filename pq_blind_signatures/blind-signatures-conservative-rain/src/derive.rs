//  Derivation helpers for the NIBS -- mixed LowMC + Rain edition.
//
//  In-the-clear mirrors of the circuit gadgets (owf_proof_lowmc.inc,
//  parameters_lowmc.hpp):
//    derive_pkr      <-> GadA : pkR = E^PRF_skR( PT(DOM_PK, open) )
//    derive_com      <-> Gad1 : com = MMO_LowMC(pkR, PT(DOM_COM, nonce))
//    (target t)      <-> Gad2 : t   = Rain(com | salt | 0xff-cap)
//                               -- lives inside MAYO's
//                                  sign_fixed_length_rain, signer side;
//                                  Rain (not LowMC) because it composes
//                                  better with VOLEitH (discussion pt. 3)
//    derive_message  <-> GadM : m   = E^PRF_skR( PT(DOM_M, nonce) )
//
//  BCGY24 (eprint 2024/614, App. B/D p.81) fidelity notes:
//   * pkR = Com(skR; open): the opening randomness `open` restores the
//     Com(K; s) shape of the generic construction. skR is the PRF key K;
//     (skR, open) together are the receiver secret key.
//   * `nonce` is signer-sampled public randomness, output by Issue alongside
//     the presignature (paper syntax), not an externally supplied context.
//
//  Domain separation lives in plaintext byte 0 (DOM_* below). The two
//  skR-keyed calls (pkR, m) have structurally distinct plaintexts for EVERY
//  (open, nonce), so a signer can never steer inputs to force m = pkR.
//
//  Security note for the write-up: pseudorandomness of m (and hiding of pkR)
//  is a standard multi-query PRF claim on LowMC(n=256, k=256, 85 boxes,
//  13 rounds, data <= 2^64); binding of com rests on MMO over the 22-round
//  max-data instance (ideal-cipher-style); binding of t is Rain's collision
//  resistance, inherited unchanged from the interactive scheme.

use vole_rainhash_then_mayo_sys::lowmc::{
    nibs_derive_com, nibs_derive_message, nibs_derive_pkr, nibs_lowmc_init,
};

pub const SKR_BYTES: usize = 32; // 256-bit LowMC key (the PRF key K)
pub const OPEN_BYTES: usize = 16; // commitment opening randomness s
pub const NONCE_BYTES: usize = 16; // signer-sampled nonce
pub const PKR_BYTES: usize = 32;
pub const SALT_BYTES: usize = 16;
pub const MSG_BYTES: usize = 32;

//  Plaintext domain bytes -- keep in sync with lowmc_plain/lowmc.hpp and
//  parameters_lowmc.hpp. (Byte values, not 16-byte lanes.)
pub const DOM_PK: u8 = 0x01;
pub const DOM_M: u8 = 0x02;
pub const DOM_COM: u8 = 0x03;

/// Must run once before any derivation (idempotent). Instantiates both
/// LowMC instances from the reference PRG stream in the fixed order
/// HASH-then-PRF; see lowmc.hpp for why the order is load-bearing.
pub fn lowmc_setup() {
    unsafe { nibs_lowmc_init() };
}

//  pkR = Com(skR; open) = E^PRF_skR( [DOM_PK, open, 0..0] )  -- mirrors GadA.
pub fn derive_pkr(sk_r: &[u8], open: &[u8]) -> Vec<u8> {
    assert_eq!(sk_r.len(), SKR_BYTES);
    assert_eq!(open.len(), OPEN_BYTES);
    let mut pkr = vec![0u8; PKR_BYTES];
    unsafe { nibs_derive_pkr(sk_r.as_ptr(), open.as_ptr(), pkr.as_mut_ptr()) };
    pkr
}

//  com = MMO_LowMC( pkR, [DOM_COM, nonce, 0..0] )   -- mirrors Gad1.
//  Used by BOTH the signer (Issue, in the clear -- this is what makes the
//  scheme non-interactive: the signer needs only (pkR, nonce)) and the
//  recipient (presignature check in Obtain).
pub fn derive_com(pk_r: &[u8], nonce: &[u8]) -> Vec<u8> {
    assert_eq!(pk_r.len(), PKR_BYTES);
    assert_eq!(nonce.len(), NONCE_BYTES);
    let mut com = vec![0u8; 32];
    unsafe { nibs_derive_com(pk_r.as_ptr(), nonce.as_ptr(), com.as_mut_ptr()) };
    com
}

//  m = E^PRF_skR( [DOM_M, nonce, 0..0] )   -- mirrors GadM, whose output is
//  constrained against the PUBLIC m. PRF security of LowMC under skR is
//  what gives receiver blindness; determinism in (skR, nonce) is what
//  one-more unforgeability's counting argument needs.
pub fn derive_message(sk_r: &[u8], nonce: &[u8]) -> Vec<u8> {
    assert_eq!(sk_r.len(), SKR_BYTES);
    assert_eq!(nonce.len(), NONCE_BYTES);
    let mut m = vec![0u8; MSG_BYTES];
    unsafe { nibs_derive_message(sk_r.as_ptr(), nonce.as_ptr(), m.as_mut_ptr()) };
    m
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn derivations_are_deterministic_and_domain_separated() {
        lowmc_setup();
        let skr = vec![0xA5u8; SKR_BYTES];
        let open = vec![0x5Au8; OPEN_BYTES];
        let nonce = vec![0x11u8; NONCE_BYTES];
        let pkr = derive_pkr(&skr, &open);
        let m = derive_message(&skr, &nonce);
        assert_eq!(pkr, derive_pkr(&skr, &open));
        assert_eq!(m, derive_message(&skr, &nonce));
        assert_ne!(pkr, m); // structural, holds for every (open, nonce)

        // a different opening yields a different commitment (hiding hook)
        let open2 = vec![0x5Bu8; OPEN_BYTES];
        assert_ne!(pkr, derive_pkr(&skr, &open2));

        let com = derive_com(&pkr, &nonce);
        assert_eq!(com.len(), 32);
    }
}
