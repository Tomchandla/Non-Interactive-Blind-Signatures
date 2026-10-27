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

    /// Presignature on the fixed-length NIBS message `m = r || pk_R`: MAYO
    /// with the Rain target `T(m || salt)`. The output is `s || salt`.
    pub fn sign_nibs(&self, sk: &MAYOSkType, m: &MAYOMessageType) -> MAYOSignatureType {
        let mut sig_len = 0usize;
        let mut sig = vec![0u8; self.mayo_params.sig_bytes];
        assert_eq!(MAYO_OK, unsafe {
            crate::mayo_nibs_sign(
                &self.mayo_params.mayo_param_set,
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

    pub fn verify_nibs(&self, pk: &MAYOPkType, m: &MAYOMessageType, sig: &MAYOSignatureType) -> bool {
        MAYO_OK
            == unsafe {
                crate::mayo_nibs_verify(
                    &self.mayo_params.mayo_param_set,
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
    fn mayo_nibs_sign_all_levels() {
        for (set, msg_len) in [
            (MAYOParameterSet::MAYO1, 48usize),
            (MAYOParameterSet::MAYO3, 72),
            (MAYOParameterSet::MAYO5, 96),
        ] {
            let mayo = MAYO::setup(set);
            let (pk, sk) = mayo.keygen();
            let m = vec![42u8; msg_len];
            let sig = mayo.sign_nibs(&sk, &m);
            assert_eq!(sig.len(), mayo.mayo_params.sig_bytes);
            assert!(mayo.verify_nibs(&pk, &m, &sig));
            let mut bad = m.clone();
            bad[0] ^= 1;
            assert!(!mayo.verify_nibs(&pk, &bad, &sig));
            let mut bad_salt = sig.clone();
            *bad_salt.last_mut().unwrap() ^= 1;
            assert!(!mayo.verify_nibs(&pk, &m, &bad_salt));
        }
    }
}
