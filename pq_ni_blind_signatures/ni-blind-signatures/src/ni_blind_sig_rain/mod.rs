use crate::zk::vole_rain_then_mayo::{VOLERainThenMAYO, proof_state::VOLERainThenMAYOProof};
use mayo_c_rain_sys::mayo::{MAYO, MAYOPkType, MAYOSignatureType, MAYOSkType};

pub mod issue;
pub mod keygen;
pub mod obtain;
pub mod verify;
pub mod setup;

// signer side
pub type SkType = MAYOSkType;
pub type PkType = MAYOPkType;

// receiver side
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientSk {
    pub key: Vec<u8>,
    pub opening: Vec<u8>,
}
pub type RecipientSkType = RecipientSk;
pub type RecipientPkType = Vec<u8>;
pub type NonceType = Vec<u8>;

// ---- protocol objects ----
pub type PresignatureType = MAYOSignatureType;
pub type DerivedMessageType = Vec<u8>;
pub type SignatureType = VOLERainThenMAYOProof;

/// Byte lengths -- must match parameters_lowmc.hpp (NIST L1, lambda = 128).
pub const SKR_BYTES: usize = 16; // K
pub const OPEN_BYTES: usize = 16; // op
pub const NONCE_BYTES: usize = 16; // r
pub const PKR_BYTES: usize = 32; // c = trunc_256(Rain(op || K))
pub const M_BYTES: usize = 16; // m = LowMC_K(r)

pub struct NibsLowmc {
    pub lambda: usize,
    pub mayo: MAYO,
    pub vole_rain_then_mayo: VOLERainThenMAYO,
}

pub fn presig_message(pk_r: &RecipientPkType, nonce: &NonceType) -> Vec<u8> {
    debug_assert_eq!(pk_r.len(), PKR_BYTES);
    debug_assert_eq!(nonce.len(), NONCE_BYTES);
    [pk_r.as_slice(), nonce.as_slice()].concat()
}

// Transitional alias so existing call sites keep compiling. Fix in due course.
pub type NibsRain = NibsLowmc;
