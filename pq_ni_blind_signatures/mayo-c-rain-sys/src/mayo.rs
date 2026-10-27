//! The MAYO signature scheme that binds to the functions from C.

mod key_expansion;
mod parameters;
mod test;

pub use parameters::{MAYOParameterSet, MAYOParameters};

use crate::{MAYO_OK, mayo_keypair};

pub type MAYOSkType = Vec<u8>;
pub type MAYOPkType = Vec<u8>;
pub type MAYOEPkType = Vec<u8>;
pub type MAYOMessageType = Vec<u8>;
pub type MAYOSignatureType = Vec<u8>;

pub struct MAYO {
    pub mayo_params: MAYOParameters,
}

impl MAYO {
    // Initializes the MAYO signature struct, 
    // where the user can choose a [`MAYOParameterSet`].
    // This will be implemented in the near future
    pub fn setup(params: MAYOParameterSet) -> Self {
        Self {
            mayo_params: MAYOParameters::setup(params),
        }
    }

    pub fn keygen(&self) -> (MAYOPkType, MAYOSkType) {
        let mut pk: Vec<u8> = vec![0; self.mayo_params.cpk_bytes];
        let mut sk: Vec<u8> = vec![0; self.mayo_params.csk_bytes];

        assert_eq!(MAYO_OK, unsafe {
            mayo_keypair(
                &self.mayo_params.mayo_param_set,
                pk.as_mut_ptr(),
                sk.as_mut_ptr(),
            ) as u32
        });
        (pk, sk)
    }

    /// NIST level (1, 3, 5) of this parameter set as used by NIBS.
    pub fn nibs_level(&self) -> u32 {
        unsafe { crate::mayo_nibs_level(&self.mayo_params.mayo_param_set) as u32 }
    }

    /// Presignature on the fixed-length NIBS message `m` (`r || pk_R` or `pk_R || r`).
    ///
    /// * `omm = false`: standard MAYO with the Rain target `T(m || salt)`;
    ///   the output is `s || salt`.
    /// * `omm = true`: One-More-MAYO, a preimage of `T(m)` without salt;
    ///   the output is `s`.
    pub fn sign_nibs(&self, sk: &MAYOSkType, m: &MAYOMessageType, omm: bool) -> MAYOSignatureType {
        let mut sig_len = 0usize;
        let mut sig = vec![0u8; self.mayo_params.sig_bytes];
        assert_eq!(MAYO_OK, unsafe {
            crate::mayo_nibs_sign(
                &self.mayo_params.mayo_param_set,
                omm as i32,
                sig.as_mut_ptr(),
                &mut sig_len,
                m.as_ptr(),
                m.len(),
                sk.as_ptr(),
            ) as u32
        });
        sig.truncate(sig_len);
        sig
    }

    pub fn verify_nibs(
        &self,
        pk: &MAYOPkType,
        m: &MAYOMessageType,
        sig: &MAYOSignatureType,
        omm: bool,
    ) -> bool {
        MAYO_OK
            == unsafe {
                crate::mayo_nibs_verify(
                    &self.mayo_params.mayo_param_set,
                    omm as i32,
                    m.as_ptr(),
                    m.len(),
                    sig.as_ptr(),
                    sig.len(),
                    pk.as_ptr(),
                ) as u32
            }
    }
}

#[cfg(test)]
mod test_mayo_nibs {
    use crate::mayo::{MAYO, MAYOParameterSet};

    #[test]
    fn mayo_nibs_sign_both_modes_all_levels() {
        for (set, msg_len) in [
            (MAYOParameterSet::MAYO1, 48usize),
            (MAYOParameterSet::MAYO3, 72),
            (MAYOParameterSet::MAYO5, 96),
        ] {
            let mayo = MAYO::setup(set);
            let (pk, sk) = mayo.keygen();
            let m = vec![42u8; msg_len];
            for omm in [false, true] {
                let sig = mayo.sign_nibs(&sk, &m, omm);
                let expect = mayo.mayo_params.sig_bytes - if omm { mayo.mayo_params.salt_bytes } else { 0 };
                assert_eq!(sig.len(), expect);
                assert!(mayo.verify_nibs(&pk, &m, &sig, omm));
                let mut bad = m.clone();
                bad[0] ^= 1;
                assert!(!mayo.verify_nibs(&pk, &bad, &sig, omm));
                // the two modes are not interchangeable
                assert!(!mayo.verify_nibs(&pk, &m, &sig, !omm));
            }
        }
    }
}
