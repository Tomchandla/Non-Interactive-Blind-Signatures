//! Non-interactive blind signatures from MAYO, LowMC, RainHash and
//! VOLE-in-the-Head.
//!
//! ```text
//! Setup      : pick NibsParams (framework, MAYO mode, VOLEitH set)
//! KeyGenS    : (vk, sk) <- MAYO.KeyGen
//! KeyGenR    : K, op <-$ ; pk_R = Rain(op||K)            (BCGY)
//!                         pk_R = P_K(0||c0) || P_K(0||c1) (sPRP)
//! Issue      : r <-$ ; presig <- MAYO.Sign(sk, r || pk_R)  (salted or One-More)
//! Obtain     : check presig; m = P_K(r) (BCGY) / P_K(1||r) (sPRP);
//!              sigma <- VOLEitH.Prove((vk, m), (presig, r, K, op))
//! Verify     : VOLEitH.Verify((vk, m), sigma)
//! ```
//!
//! The Fiat–Shamir transcript of every proof is bound to the statement via
//! `fs_context = SHAKE256("NIBS-FS-v1" || instance || vk || m)`.

use crate::params::NibsParams;
use crate::zk::{self, InstanceInfo};
use mayo_c_rain_sys::mayo::{MAYO, MAYOParameterSet};
use mayo_c_rain_sys::shake256;

pub mod issue;
pub mod keygen;
pub mod obtain;
pub mod verify;

/// MAYO compressed public key (the NIBS verification key vk).
pub type PkType = Vec<u8>;
/// MAYO compressed secret key.
pub type SkType = Vec<u8>;
/// MAYO expanded public key (what the circuit consumes; cache it per signer).
pub type EPkType = Vec<u8>;
pub type RecipientPkType = Vec<u8>;
pub type NonceType = Vec<u8>;
pub type PresignatureType = Vec<u8>;
pub type MessageType = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientSk {
    /// LowMC key K (lambda bits)
    pub key: Vec<u8>,
    /// commitment opening op (lambda bits; empty for the sPRP framework)
    pub opening: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub proof: Vec<u8>,
}

pub struct Nibs {
    pub params: NibsParams,
    pub info: InstanceInfo,
    pub mayo: MAYO,
}

impl Nibs {
    pub fn setup(params: NibsParams) -> Self {
        let mayo_set = match params.zk.level() {
            1 => MAYOParameterSet::MAYO1,
            3 => MAYOParameterSet::MAYO3,
            _ => MAYOParameterSet::MAYO5,
        };
        vole_rainhash_then_mayo_sys::lowmc::init();
        let info = zk::instance_info(&params);
        let mayo = MAYO::setup(mayo_set);
        assert_eq!(mayo.nibs_level(), params.zk.level());
        assert_eq!(info.s_bytes, mayo.mayo_params.sig_bytes - mayo.mayo_params.salt_bytes);
        if !params.is_one_more() {
            assert_eq!(info.salt_bytes, mayo.mayo_params.salt_bytes);
        }
        Self { params, info, mayo }
    }

    pub fn level(&self) -> u32 {
        self.params.zk.level()
    }

    /// Bytes of a presignature: MAYO preimage (+ salt for standard MAYO).
    pub fn presignature_bytes(&self) -> usize {
        self.info.s_bytes + if self.params.is_one_more() { 0 } else { self.mayo.mayo_params.salt_bytes }
    }

    pub fn signature_bytes(&self) -> usize {
        self.info.proof_bytes
    }

    pub fn expand_pk(&self, pk: &PkType) -> EPkType {
        self.mayo.expand_pk(pk)
    }

    /// The MAYO message `M = r || pk_R` (the pair (pk_R, r) of the paper,
    /// encoded nonce first so that the first Rain block of the target hash
    /// always contains the signer's fresh randomness).
    pub fn presig_message(&self, pk_r: &RecipientPkType, nonce: &NonceType) -> Vec<u8> {
        assert_eq!(pk_r.len(), self.info.pkr_bytes);
        assert_eq!(nonce.len(), self.info.r_bytes);
        [nonce.as_slice(), pk_r.as_slice()].concat()
    }

    /// Fiat–Shamir context binding the instance and the statement (vk, m).
    pub fn fs_context(&self, pk: &PkType, m: &MessageType) -> [u8; 32] {
        let p = &self.params;
        let mut input = b"NIBS-FS-v1".to_vec();
        input.extend_from_slice(&[
            p.variant_id() as u8,
            p.zk.level() as u8,
            p.zk.speed() as u8,
            p.zk.version() as u8,
        ]);
        input.extend_from_slice(&(pk.len() as u32).to_le_bytes());
        input.extend_from_slice(pk);
        input.extend_from_slice(&(m.len() as u32).to_le_bytes());
        input.extend_from_slice(m);
        let mut out = [0u8; 32];
        unsafe { shake256(out.as_mut_ptr(), out.len(), input.as_ptr(), input.len()) };
        out
    }
}
