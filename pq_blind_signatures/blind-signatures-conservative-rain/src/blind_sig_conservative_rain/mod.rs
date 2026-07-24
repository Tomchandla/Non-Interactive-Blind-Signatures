use crate::zk::vole_rain_then_mayo::{VOLERainThenMAYO, proof_state::VOLERainThenMAYOProof};
use mayo_c_rain_sys::mayo::{MAYO, MAYOPkType, MAYOSignatureType, MAYOSkType};

pub mod issue;
pub mod keygen;
pub mod obtain;
pub mod verify;
pub mod setup;

// ---- signer side (unchanged MAYO types) ----
pub type SkType = MAYOSkType;
pub type PkType = MAYOPkType;

// ---- recipient side ----
/// Recipient secret key: the LowMC PRF key K plus the commitment opening
/// randomness s (BCGY24: sk_R = (K, s), pk_R = Com(K; s)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientSk {
    /// 256-bit LowMC key (SKR_BYTES).
    pub key: Vec<u8>,
    /// 128-bit opening randomness (OPEN_BYTES).
    pub opening: Vec<u8>,
}
pub type RecipientSkType = RecipientSk;
/// Recipient public key: pkR = Com(skR; open) = E^PRF_skR(PT(DOM_PK, open)),
/// 32 bytes.
pub type RecipientPkType = Vec<u8>;
/// Signer-sampled per-issuance nonce (paper syntax: output of Issue).
pub type NonceType = Vec<u8>;

// ---- protocol objects ----
/// Presignature: a raw MAYO preimage+salt on the target derived from
/// (pkR, nonce).
pub type PresignatureType = MAYOSignatureType;
/// The derived (pseudorandom) message m = E^PRF_skR(PT(DOM_M, nonce)), 32 B.
pub type DerivedMessageType = Vec<u8>;
/// The blind signature on m: a single VOLEitH proof.
pub type SignatureType = VOLERainThenMAYOProof;

/// Byte lengths -- must match parameters_lowmc.hpp.
pub const SKR_BYTES: usize = 32;
pub const OPEN_BYTES: usize = 16;
pub const NONCE_BYTES: usize = 16;
pub const PKR_BYTES: usize = 32;
pub const M_BYTES: usize = 32;

/// NIBS instance: MAYO + the MIXED LowMC/Rain VOLEitH circuit
///   GadA (LowMC PRF) : pkR = E^PRF_skR(PT(DOM_PK, open))   (wit skR, open)
///   Gad1 (LowMC MMO) : com = MMO(pkR, PT(DOM_COM, nonce))  (wit nonce)
///   Gad2 (Rain)      : t   = Rain(com | salt | cap)        (wit com', salt;
///                       com' bound to Gad1's com by 256 seam equalities)
///   MAYO             : T*(s) = t                           (wit s)
///   GadM (LowMC PRF) : m   = E^PRF_skR(PT(DOM_M, nonce))   (output m PUBLIC)
///
/// This is the generic NIBS of BCGY24 (eprint 2024/614, App. B/D p.81)
/// instantiated with PRF/commitment = LowMC, signature = MAYO,
/// NIZK = VOLEitH; Rain is retained exactly where MAYO's hash-then-sign
/// needs a hash, because Rain composes better with VOLEitH.
pub struct NibsLowmc {
    pub lambda: usize,
    pub mayo: MAYO,
    pub vole_rain_then_mayo: VOLERainThenMAYO,
}

/// Transitional alias so existing call sites keep compiling.
pub type NibsRain = NibsLowmc;
