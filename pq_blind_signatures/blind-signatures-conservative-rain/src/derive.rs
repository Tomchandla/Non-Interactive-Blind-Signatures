use vole_rainhash_then_mayo_sys::lowmc::{
    nibs_derive_message, nibs_derive_pkr, nibs_lowmc_init,
};

pub const SKR_BYTES: usize = 32; // 256-bit LowMC key (the PRF key K)
pub const OPEN_BYTES: usize = 16; // commitment opening randomness s
pub const NONCE_BYTES: usize = 16; // signer-sampled nonce
pub const PKR_BYTES: usize = 32;
pub const SALT_BYTES: usize = 24;
pub const MSG_BYTES: usize = 32;
pub const PRESIG_MSG_BYTES:usize = PKR_BYTES + NONCE_BYTES;

//  Plaintext domain bytes
pub const DOM_PK: u8 = 0x01;
pub const DOM_M: u8 = 0x02;

pub fn lowmc_setup() {
    unsafe { nibs_lowmc_init() };
}

pub fn derive_pkr(sk_r: &[u8], open: &[u8]) -> Vec<u8> {
    assert_eq!(sk_r.len(), SKR_BYTES);
    assert_eq!(open.len(), OPEN_BYTES);
    let mut pkr = vec![0u8; PKR_BYTES];
    unsafe { nibs_derive_pkr(sk_r.as_ptr(), open.as_ptr(), pkr.as_mut_ptr()) };
    pkr
}

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
    fn derivations_are_deterministic() {
        lowmc_setup();
        let skr = vec![0xA5u8; SKR_BYTES];
        let open = vec![0x5Au8; OPEN_BYTES];
        let nonce = vec![0x11u8; NONCE_BYTES];
        assert_eq!(derive_pkr(&skr, &open), derive_pkr(&skr, &open));
        assert_eq!(derive_message(&skr, &nonce), derive_message(&skr, &nonce));
    }

    #[test]
    fn domain_bytes_actually_separate() {
        lowmc_setup();
        let skr = vec![0xA5u8; SKR_BYTES];
        let payload = vec![0x11u8; OPEN_BYTES]; // OPEN_BYTES == NONCE_BYTES
        assert_ne!(derive_pkr(&skr, &payload), derive_message(&skr, &payload));
    }

    #[test]
    fn distinct_keys_separate_outputs() {
        lowmc_setup();
        let k1 = vec![0xA5u8; SKR_BYTES];
        let k2 = vec![0xA6u8; SKR_BYTES];
        let payload = vec![0x11u8; NONCE_BYTES];
        assert_ne!(derive_pkr(&k1, &payload), derive_pkr(&k2, &payload));
        assert_ne!(derive_message(&k1, &payload), derive_message(&k2, &payload));
    }

    #[test]
    fn distinct_openings_give_distinct_pkr() {
        lowmc_setup();
        let skr = vec![0xA5u8; SKR_BYTES];
        let pkr = derive_pkr(&skr, &vec![0x5Au8; OPEN_BYTES]);
        assert_ne!(pkr, derive_pkr(&skr, &vec![0x5Bu8; OPEN_BYTES]));
    }
}
