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

/// This struct acts as the object callable to utilize the functionalities of MAYO.
/// With it, you can sign and validate messages using different parametersets.
///
/// # Example
/// ```
/// use mayo_c_sys::mayo::*;
/// use mayo_c_sys::mayo::MAYOParameters;
///
/// // initialize with MAYO_5 parameters
/// let mayo = MAYO::setup(MAYOParameterSet::MAYO5);
///
/// let (pk, sk) = mayo.keygen();
/// let m = vec![0; 32];
/// let sig = mayo.sign(&sk, &m);
///
/// assert!(mayo.verify(&pk, &m, &sig))
/// ```
pub struct MAYO {
    pub mayo_params: MAYOParameters,
}

impl MAYO {
    /// Initializes the MAYO signature struct, where the user can choose a [`MAYOParameterSet`].
    ///
    /// # Params
    /// - `params`: Defines which parameterset is chosen
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::*;
    /// use mayo_c_sys::mayo::MAYOParameters;
    ///
    /// // initialize with MAYO_1 parameters
    /// let mayo1 = MAYO::setup(MAYOParameterSet::MAYO1);
    /// // initialize with MAYO_2 parameters
    /// let mayo2 = MAYO::setup(MAYOParameterSet::MAYO2);
    /// // initialize with MAYO_3 parameters
    /// let mayo3 = MAYO::setup(MAYOParameterSet::MAYO3);
    /// // initialize with MAYO_5 parameters
    /// let mayo5 = MAYO::setup(MAYOParameterSet::MAYO5);
    /// ```
    pub fn setup(params: MAYOParameterSet) -> Self {
        Self {
            mayo_params: MAYOParameters::setup(params),
        }
    }

    /// Generates a keypair consisting of a public key and a secret key.
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::*;
    /// use mayo_c_sys::mayo::MAYOParameters;
    ///
    /// // initialize with MAYO_5 parameters
    /// let mayo5 = MAYO::setup(MAYOParameterSet::MAYO5);
    /// // generate the keys
    /// let (pk, sk) = mayo5.keygen();
    /// ```
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

    /// Given a secret key and a message, the algorithm produces a signature.
    ///
    /// # Params
    /// - `sk`: The secret key with which is signed
    /// - `m`: The message that is signed
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::*;
    /// use mayo_c_sys::mayo::MAYOParameters;
    ///
    /// // initialize with MAYO_5 parameters
    /// let mayo5 = MAYO::setup(MAYOParameterSet::MAYO5);
    /// // generate the keys
    /// let (pk, sk) = mayo5.keygen();
    ///
    /// let m = vec![42, 21, 17, 35, 10];
    /// let sig = mayo5.sign(&sk, &m);
    /// ```
    pub fn sign(&self, sk: &MAYOSkType, m: &MAYOMessageType) -> MAYOSignatureType {
        let mut sig_len = 0; // not important for us
        let mut sig = vec![0; self.mayo_params.sig_bytes + m.len()];

        assert_eq!(MAYO_OK, unsafe {
            crate::mayo_sign(
                &self.mayo_params.mayo_param_set,
                sig.as_mut_ptr(),
                &mut sig_len,
                m.as_ptr(),
                m.len(),
                sk.as_ptr(),
            ) as u32
        });

        sig
    }

    /// Given a secret key and a message, the algorithm produces a preimage of a value t.
    ///
    /// # Params
    /// - `sk`: The secret key with which is signed
    /// - `t`: The value  for which a preimage is to be generated
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::*;
    /// use mayo_c_sys::*;
    /// use mayo_c_sys::mayo::MAYOParameters;
    ///
    /// // initialize with MAYO_5 parameters
    /// let mayo5 = MAYO::setup(MAYOParameterSet::MAYO5);
    /// // generate the keys
    /// let (pk, sk) = mayo5.keygen();
    ///
    /// let m = vec![42, 21, 17, 35, 10];
    /// let mut t = vec![0; MAYO_5_m_bytes as usize];
    /// unsafe { shake256(t.as_mut_ptr(), t.len(), m.as_ptr(), m.len()) };
    ///
    /// let sig = mayo5.sample_preimage(&sk, &t);
    /// ```
    pub fn sample_preimage(&self, sk: &MAYOSkType, t: &MAYOMessageType) -> MAYOSignatureType {
        let mut sig_len = 0; // not important for us
        let mut sig = vec![0; self.mayo_params.sig_bytes - self.mayo_params.salt_bytes];
        assert_eq!(MAYO_OK, unsafe {
            crate::mayo_sign_without_hashing(
                &self.mayo_params.mayo_param_set,
                sig.as_mut_ptr(),
                &mut sig_len,
                t.as_ptr(),
                t.len(),
                sk.as_ptr(),
            ) as u32
        });

        sig
    }

    /// Given a secret key and a message, the algorithm produces a signature.
    ///
    /// # Params
    /// - `sk`: The secret key with which is signed
    /// - `m`: The message that is signed
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::*;
    /// use mayo_c_sys::mayo::MAYOParameterSet;
    ///
    /// // initialize with MAYO_5 parameters
    /// let mayo5 = MAYO::setup(MAYOParameterSet::MAYO5);
    /// // generate the keys
    /// let (pk, sk) = mayo5.keygen();
    ///
    /// let m = vec![0; mayo5.mayo_params.m_digest_bytes];
    /// let sig = mayo5.sign_fixed_length(&sk, &m);
    /// ```
    pub fn sign_fixed_length(&self, sk: &MAYOSkType, m: &MAYOMessageType) -> MAYOSignatureType {
        let mut sig_len = 0; // not important for us
        let mut sig = vec![0; self.mayo_params.sig_bytes];

        assert_eq!(MAYO_OK, unsafe {
            crate::mayo_sign_fixed_length_input(
                &self.mayo_params.mayo_param_set,
                sig.as_mut_ptr(),
                &mut sig_len,
                m.as_ptr(),
                m.len(),
                sk.as_ptr(),
            ) as u32
        });

        sig
    }

    /// Given a public key, a message and a signature, the algorithm verifies whether the signature is correct.
    ///
    /// # Params
    /// - `pk`: The public key used for verification
    /// - `m`: The message for which the signature is verified
    /// - `sig`: The signature that is tested for validity
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::*;
    /// use mayo_c_sys::mayo::MAYOParameters;
    ///
    /// // initialize with MAYO_5 parameters
    /// let mayo5 = MAYO::setup(MAYOParameterSet::MAYO5);
    /// // generate the keys
    /// let (pk, sk) = mayo5.keygen();
    ///
    /// let m = vec![42, 21, 17, 35, 10];
    ///
    /// let sig = mayo5.sign(&sk, &m);
    ///
    /// assert!(mayo5.verify(&pk, &m, &sig));
    /// ```
    pub fn verify(&self, pk: &MAYOPkType, m: &MAYOMessageType, sig: &MAYOSignatureType) -> bool {
        MAYO_OK
            == unsafe {
                crate::mayo_verify(
                    &self.mayo_params.mayo_param_set,
                    m.as_ptr(),
                    m.len(),
                    sig.as_ptr(),
                    pk.as_ptr(),
                ) as u32
            }
    }

    /// Given a public key, a message and a signature, the algorithm verifies whether the signature is correct,
    /// but it treats the input as the hash of the message, i.e. it just evaluates if `sig` is actually a preimage of `t`.
    ///
    /// # Params
    /// - `pk`: The public key used for verification
    /// - `t`: The message for which the signature is verified
    /// - `sig`: The signature that is tested for validity
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::*;
    /// use mayo_c_sys::*;
    /// use mayo_c_sys::mayo::MAYOParameterSet;
    ///
    /// // initialize with MAYO_5 parameters
    /// let mayo5 = MAYO::setup(MAYOParameterSet::MAYO5);
    /// // generate the keys
    /// let (pk, sk) = mayo5.keygen();
    ///
    /// let m = vec![42, 21, 17, 35, 10];
    /// let mut t = vec![0; MAYO_5_m_bytes as usize];
    /// unsafe { shake256(t.as_mut_ptr(), t.len(), m.as_ptr(), m.len()) };
    ///
    /// let sig = mayo5.sample_preimage(&sk, &t);
    /// assert!(mayo5.verify_without_hashing(&pk, &t, &sig))
    /// ```
    pub fn verify_without_hashing(
        &self,
        pk: &MAYOPkType,
        t: &MAYOMessageType,
        sig: &MAYOSignatureType,
    ) -> bool {
        MAYO_OK
            == unsafe {
                crate::mayo_verify_without_hashing(
                    &self.mayo_params.mayo_param_set,
                    t.as_ptr(),
                    t.len(),
                    sig.as_ptr(),
                    pk.as_ptr(),
                ) as u32
            }
    }

    /// Given a public key, a message and a signature, the algorithm verifies whether the signature is correct.
    ///
    /// # Params
    /// - `pk`: The public key used for verification
    /// - `m`: The message for which the signature is verified
    /// - `sig`: The signature that is tested for validity
    ///
    /// # Example
    /// ```
    /// use mayo_c_sys::mayo::*;
    /// use mayo_c_sys::mayo::MAYOParameterSet;
    ///
    /// // initialize with MAYO_5 parameters
    /// let mayo5 = MAYO::setup(MAYOParameterSet::MAYO5);
    /// // generate the keys
    /// let (pk, sk) = mayo5.keygen();
    ///
    /// let m = vec![0; mayo5.mayo_params.m_digest_bytes];
    ///
    /// let sig = mayo5.sign_fixed_length(&sk, &m);
    ///
    /// assert!(mayo5.verify_fixed_length(&pk, &m, &sig));
    /// ```
    pub fn verify_fixed_length(
        &self,
        pk: &MAYOPkType,
        m: &MAYOMessageType,
        sig: &MAYOSignatureType,
    ) -> bool {
        MAYO_OK
            == unsafe {
                crate::mayo_verify_fixed_length_input(
                    &self.mayo_params.mayo_param_set,
                    m.as_ptr(),
                    m.len(),
                    sig.as_ptr(),
                    pk.as_ptr(),
                ) as u32
            }
    }
}

#[cfg(test)]
mod test_each_parameter_set {
    use super::{MAYO, MAYOParameterSet};

    #[test]
    fn test_parameter_set_mayo_1() {
        let mayo = MAYO::setup(MAYOParameterSet::MAYO1);
        let (pk, sk) = mayo.keygen();
        let m = vec![42, 21];
        let sig = mayo.sign(&sk, &m);
        assert!(mayo.verify(&pk, &m, &sig))
    }

    #[test]
    fn test_parameter_set_mayo_2() {
        let mayo = MAYO::setup(MAYOParameterSet::MAYO2);
        let (pk, sk) = mayo.keygen();
        let m = vec![2; 32];
        let sig = mayo.sign(&sk, &m);

        assert!(mayo.verify(&pk, &m, &sig))
    }
    #[test]
    fn test_parameter_set_mayo_3() {
        let mayo = MAYO::setup(MAYOParameterSet::MAYO3);
        let (pk, sk) = mayo.keygen();
        let m = vec![3; 64];
        let sig = mayo.sign(&sk, &m);

        assert!(mayo.verify(&pk, &m, &sig))
    }
    #[test]
    fn test_parameter_set_mayo_5() {
        let mayo = MAYO::setup(MAYOParameterSet::MAYO5);
        let (pk, sk) = mayo.keygen();
        let m = vec![0; 32];
        let sig = mayo.sign(&sk, &m);

        assert!(mayo.verify(&pk, &m, &sig))
    }
}

#[cfg(test)]
mod test_sign_without_hashing {
    use crate::mayo::{MAYO, MAYOParameterSet};
    use crate::{MAYO_2_m_bytes, shake256};

    #[test]
    fn correct_signature_is_accepted() {
        let mayo = MAYO::setup(MAYOParameterSet::MAYO2);
        let (pk, sk) = mayo.keygen();

        // hash the message
        let m = [42, 21];
        let mut t = vec![0; MAYO_2_m_bytes as usize];
        unsafe { shake256(t.as_mut_ptr(), t.len(), m.as_ptr(), m.len()) };

        let sig = mayo.sample_preimage(&sk, &t);

        assert!(mayo.verify_without_hashing(&pk, &t, &sig))
    }

    #[test]
    #[should_panic]
    fn wrong_input_size() {
        let mayo = MAYO::setup(MAYOParameterSet::MAYO2);
        let (_, sk) = mayo.keygen();

        let t = vec![0; (MAYO_2_m_bytes - 1) as usize];

        mayo.sample_preimage(&sk, &t);
    }
}

#[cfg(test)]
mod test_sign_with_fixed_length {
    use crate::mayo::{MAYO, parameters::MAYOParameterSet};

    #[test]
    fn correct_signature_is_accepted_mayo_1() {
        // initialize with MAYO_1 parameters
        let mayo = MAYO::setup(MAYOParameterSet::MAYO1);
        // generate the keys
        let (pk, sk) = mayo.keygen();

        let mut m = vec![0; mayo.mayo_params.m_digest_bytes];
        m[0] = 42;
        m[2] = 24;
        let sig = mayo.sign_fixed_length(&sk, &m);

        assert!(mayo.verify_fixed_length(&pk, &m, &sig));
    }

    #[test]
    fn correct_signature_is_accepted_mayo_2() {
        // initialize with MAYO_2 parameters
        let mayo = MAYO::setup(MAYOParameterSet::MAYO2);
        // generate the keys
        let (pk, sk) = mayo.keygen();

        let mut m = vec![0; mayo.mayo_params.m_digest_bytes];
        m[0] = 42;
        m[2] = 24;
        let sig = mayo.sign_fixed_length(&sk, &m);

        assert!(mayo.verify_fixed_length(&pk, &m, &sig));
    }

    #[test]
    fn correct_signature_is_accepted_mayo_3() {
        // initialize with MAYO_3 parameters
        let mayo = MAYO::setup(MAYOParameterSet::MAYO3);
        // generate the keys
        let (pk, sk) = mayo.keygen();

        let mut m = vec![0; mayo.mayo_params.m_digest_bytes];
        m[0] = 42;
        m[2] = 24;
        let sig = mayo.sign_fixed_length(&sk, &m);

        assert!(mayo.verify_fixed_length(&pk, &m, &sig));
    }

    #[test]
    fn correct_signature_is_accepted_mayo_5() {
        // initialize with MAYO_5 parameters
        let mayo = MAYO::setup(MAYOParameterSet::MAYO5);
        // generate the keys
        let (pk, sk) = mayo.keygen();

        let mut m = vec![0; mayo.mayo_params.m_digest_bytes];
        m[0] = 42;
        m[2] = 24;
        let sig = mayo.sign_fixed_length(&sk, &m);

        assert!(mayo.verify_fixed_length(&pk, &m, &sig));
    }
}
