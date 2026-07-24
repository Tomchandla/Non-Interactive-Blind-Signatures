//! Wrapper around the C prove/verify entry points for the MIXED
//! LowMC + Rain NIBS circuit:
//!
//!   prove:  (epk, m_pub, s, sk_r, open, nonce, salt, additional_r)
//!   verify: (proof, epk, m_pub, additional_r)
//!
//! sk_r here is the raw 256-bit LowMC key K; open is the 128-bit commitment
//! opening; nonce the signer-sampled 128-bit nonce; salt MAYO's 128-bit
//! signature salt. ProveFn in parameters.rs mirrors this order. Re-run the
//! sys-crate bindgen after touching faest.h.

use crate::zk::{
    ZKType,
    vole_rain_then_mayo::{
        parameters::VOLERainThenMAYOParameters,
        proof_state::{VOLERainThenMAYOProof, VOLERainThenMAYOProofState},
    },
};

pub mod parameters;
pub mod proof_state;

pub const VOLERAINHASH_RC_SIZE: usize = 64 * 7;
pub const VOLERAINHASH_MAT_SIZE: usize = 64 * 512 * 7;

pub static ROUND_CONST: [u8; VOLERAINHASH_RC_SIZE] = [u8::MAX; VOLERAINHASH_RC_SIZE];
pub static MAT: [u8; VOLERAINHASH_MAT_SIZE] = [u8::MAX; VOLERAINHASH_MAT_SIZE];

pub struct VOLERainThenMAYO {
    pub vole_rain_then_mayo_params: VOLERainThenMAYOParameters,
}

impl VOLERainThenMAYO {
    pub fn setup(params: ZKType) -> Self {
        VOLERainThenMAYO {
            vole_rain_then_mayo_params: VOLERainThenMAYOParameters::setup(params),
        }
    }

    /// Proof for the NIBS relation (mixed LowMC + Rain):
    ///   GadA (LowMC PRF) : E^PRF_skR(PT(DOM_PK, open))  = pkR   (witness)
    ///   Gad1 (LowMC MMO) : MMO(pkR, PT(DOM_COM, nonce)) = com   (wire expr)
    ///   Gad2 (Rain)      : Rain(com | salt | cap)       = t     (witness)
    ///   MAYO             : T*(s)                        = t     (witness s)
    ///   GadM (LowMC PRF) : E^PRF_skR(PT(DOM_M, nonce))  = m     (PUBLIC m)
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        &self,
        epk: &mut [u8],
        m_pub: &mut [u8],
        s: &mut [u8],
        sk_r: &mut [u8],
        open: &mut [u8],
        nonce: &mut [u8],
        salt: &mut [u8],
        additional_r: &mut [u8],
    ) -> VOLERainThenMAYOProof {
        let mut state = VOLERainThenMAYOProofState::init(&self.vole_rain_then_mayo_params);

        assert!(unsafe {
            (self.vole_rain_then_mayo_params.prove_fn)(
                state.proof.as_mut_ptr(),
                state.random_seed.as_mut_ptr(),
                state.random_seed.len(),
                epk.as_mut_ptr(),
                m_pub.as_mut_ptr(),
                ROUND_CONST.clone().as_mut_ptr(),
                MAT.clone().as_mut_ptr(),
                s.as_mut_ptr(),
                sk_r.as_mut_ptr(),
                open.as_mut_ptr(),
                nonce.as_mut_ptr(),
                salt.as_mut_ptr(),
                additional_r.as_mut_ptr(),
            )
        });

        VOLERainThenMAYOProof::from(state)
    }

    pub fn verify(
        &self,
        proof: &mut VOLERainThenMAYOProof,
        epk: &mut [u8],
        m_pub: &mut [u8],
        additional_r: &mut [u8],
    ) -> bool {
        unsafe {
            (self.vole_rain_then_mayo_params.verify_fn)(
                proof.proof.as_mut_ptr(),
                proof.proof.len(),
                epk.as_mut_ptr(),
                m_pub.as_mut_ptr(),
                ROUND_CONST.clone().as_mut_ptr(),
                MAT.clone().as_mut_ptr(),
                additional_r.as_mut_ptr(),
            )
        }
    }
}
