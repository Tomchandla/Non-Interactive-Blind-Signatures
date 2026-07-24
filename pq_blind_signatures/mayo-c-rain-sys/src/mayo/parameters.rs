//! This module is serves to take out any complexity w.r.t. shifting between the
//! different versions of MAYO.
//! The [`MAYOParameters`] provides a range of parameters connected to the specific
//! choice of parameters.

use crate::{
    MAYO_1, MAYO_1_P1_bytes, MAYO_1_P2_bytes, MAYO_1_P3_bytes, MAYO_1_cpk_bytes, MAYO_1_csk_bytes,
    MAYO_1_digest_bytes, MAYO_1_m, MAYO_1_m_vec_limbs, MAYO_1_o, MAYO_1_pk_seed_bytes,
    MAYO_1_salt_bytes, MAYO_1_sig_bytes, MAYO_1_v, MAYO_2, MAYO_2_P1_bytes, MAYO_2_P2_bytes,
    MAYO_2_P3_bytes, MAYO_2_cpk_bytes, MAYO_2_csk_bytes, MAYO_2_digest_bytes, MAYO_2_m,
    MAYO_2_m_vec_limbs, MAYO_2_o, MAYO_2_pk_seed_bytes, MAYO_2_salt_bytes, MAYO_2_sig_bytes,
    MAYO_2_v, MAYO_3, MAYO_3_P1_bytes, MAYO_3_P2_bytes, MAYO_3_P3_bytes, MAYO_3_cpk_bytes,
    MAYO_3_csk_bytes, MAYO_3_digest_bytes, MAYO_3_m, MAYO_3_m_vec_limbs, MAYO_3_o,
    MAYO_3_pk_seed_bytes, MAYO_3_salt_bytes, MAYO_3_sig_bytes, MAYO_3_v, MAYO_5, MAYO_5_P1_bytes,
    MAYO_5_P2_bytes, MAYO_5_P3_bytes, MAYO_5_cpk_bytes, MAYO_5_csk_bytes, MAYO_5_digest_bytes,
    MAYO_5_m, MAYO_5_m_vec_limbs, MAYO_5_o, MAYO_5_pk_seed_bytes, MAYO_5_salt_bytes,
    MAYO_5_sig_bytes, MAYO_5_v, mayo_params_t,
};

/// Just a capture for all the parameters needed in our code that we need to access in
/// respect to the MAYO-C interface.
/// They are defined by the respective [`MAYOParameterSet`].
pub struct MAYOParameters {
    pub cpk_bytes: usize,
    pub csk_bytes: usize,
    pub sig_bytes: usize,
    pub salt_bytes: usize,
    pub p1_bytes: usize,
    pub p2_bytes: usize,
    pub p3_bytes: usize,
    pub m: usize,
    pub v: usize,
    pub o: usize,
    pub pk_seed_bytes: usize,
    pub m_vec_limbs: usize,
    pub mayo_param_set: mayo_params_t,
    pub m_digest_bytes: usize,
}

impl MAYOParameters {
    /// Sets all the MAYO parameters according to their definition in MAYO-C
    pub fn setup(params: MAYOParameterSet) -> Self {
        match params {
            MAYOParameterSet::MAYO1 => Self {
                cpk_bytes: MAYO_1_cpk_bytes as usize,
                csk_bytes: MAYO_1_csk_bytes as usize,
                sig_bytes: MAYO_1_sig_bytes as usize,
                mayo_param_set: unsafe { MAYO_1 },
                salt_bytes: MAYO_1_salt_bytes as usize,
                p1_bytes: MAYO_1_P1_bytes as usize,
                p2_bytes: MAYO_1_P2_bytes as usize,
                p3_bytes: MAYO_1_P3_bytes as usize,
                m: MAYO_1_m as usize,
                v: MAYO_1_v as usize,
                o: MAYO_1_o as usize,
                pk_seed_bytes: MAYO_1_pk_seed_bytes as usize,
                m_vec_limbs: MAYO_1_m_vec_limbs as usize,
                m_digest_bytes: MAYO_1_digest_bytes as usize,
            },
            MAYOParameterSet::MAYO2 => Self {
                cpk_bytes: MAYO_2_cpk_bytes as usize,
                csk_bytes: MAYO_2_csk_bytes as usize,
                sig_bytes: MAYO_2_sig_bytes as usize,
                mayo_param_set: unsafe { MAYO_2 },
                salt_bytes: MAYO_2_salt_bytes as usize,
                p1_bytes: MAYO_2_P1_bytes as usize,
                p2_bytes: MAYO_2_P2_bytes as usize,
                p3_bytes: MAYO_2_P3_bytes as usize,
                m: MAYO_2_m as usize,
                v: MAYO_2_v as usize,
                o: MAYO_2_o as usize,
                m_vec_limbs: MAYO_2_m_vec_limbs as usize,
                pk_seed_bytes: MAYO_2_pk_seed_bytes as usize,
                m_digest_bytes: MAYO_2_digest_bytes as usize,
            },
            MAYOParameterSet::MAYO3 => Self {
                cpk_bytes: MAYO_3_cpk_bytes as usize,
                csk_bytes: MAYO_3_csk_bytes as usize,
                sig_bytes: MAYO_3_sig_bytes as usize,
                mayo_param_set: unsafe { MAYO_3 },
                salt_bytes: MAYO_3_salt_bytes as usize,
                p1_bytes: MAYO_3_P1_bytes as usize,
                p2_bytes: MAYO_3_P2_bytes as usize,
                p3_bytes: MAYO_3_P3_bytes as usize,
                m: MAYO_3_m as usize,
                v: MAYO_3_v as usize,
                o: MAYO_3_o as usize,
                m_vec_limbs: MAYO_3_m_vec_limbs as usize,
                pk_seed_bytes: MAYO_3_pk_seed_bytes as usize,
                m_digest_bytes: MAYO_3_digest_bytes as usize,
            },
            MAYOParameterSet::MAYO5 => Self {
                cpk_bytes: MAYO_5_cpk_bytes as usize,
                csk_bytes: MAYO_5_csk_bytes as usize,
                sig_bytes: MAYO_5_sig_bytes as usize,
                mayo_param_set: unsafe { MAYO_5 },
                salt_bytes: MAYO_5_salt_bytes as usize,
                p1_bytes: MAYO_5_P1_bytes as usize,
                p2_bytes: MAYO_5_P2_bytes as usize,
                p3_bytes: MAYO_5_P3_bytes as usize,
                m: MAYO_5_m as usize,
                v: MAYO_5_v as usize,
                o: MAYO_5_o as usize,
                m_vec_limbs: MAYO_5_m_vec_limbs as usize,
                pk_seed_bytes: MAYO_5_pk_seed_bytes as usize,
                m_digest_bytes: MAYO_5_digest_bytes as usize,
            },
        }
    }
}

/// This struct represents the different parametersets of MAYO.
/// Respectively, these are
/// - `MAYO_1` (NIST Level 1)
/// - `MAYO_2` (NIST Level 2)
/// - `MAYO_3` (NIST Level 3)
/// - `MAYO_5` (NIST Level 5)
///
/// More details can be found [here](https://github.com/PQCMayo/MAYO-C).
pub enum MAYOParameterSet {
    MAYO1,
    MAYO2,
    MAYO3,
    MAYO5,
}
