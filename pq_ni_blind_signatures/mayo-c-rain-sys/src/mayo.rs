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
/// use mayo_c_rain_sys::mayo::*;
/// use mayo_c_rain_sys::mayo::MAYOParameters;
///
/// // initialize with MAYO_1 parameters
/// let mayo1 = MAYO::setup(MAYOParameterSet::MAYO1);
/// // generate the keys
/// let (pk, sk) = mayo1.keygen();
///
/// let m = vec![42; mayo1.mayo_params.m_digest_bytes];
///
/// let sig = mayo1.sign_fixed_length_rain(&sk, &m);
///
/// assert!(mayo1.verify_fixed_length_rain(&pk, &m, &sig));
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
    /// use mayo_c_rain_sys::mayo::*;
    /// use mayo_c_rain_sys::mayo::MAYOParameters;
    ///
    /// // initialize with MAYO_1 parameters
    /// let mayo1 = MAYO::setup(MAYOParameterSet::MAYO1);
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
    /// use mayo_c_rain_sys::mayo::*;
    /// use mayo_c_rain_sys::mayo::MAYOParameters;
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
    /// Instead of SHAKE256, it uses the rain hash function to generate the target.
    ///
    /// # Params
    /// - `sk`: The secret key with which is signed
    /// - `m`: The message that is signed
    ///
    /// # Example
    /// ```
    /// use mayo_c_rain_sys::mayo::*;
    /// use mayo_c_rain_sys::mayo::MAYOParameterSet;
    ///
    /// // initialize with MAYO_1 parameters
    /// let mayo1 = MAYO::setup(MAYOParameterSet::MAYO1);
    /// // generate the keys
    /// let (pk, sk) = mayo1.keygen();
    ///
    /// let m = vec![0; mayo1.mayo_params.m_digest_bytes];
    /// let sig = mayo1.sign_fixed_length_rain(&sk, &m);
    /// ```
    pub fn sign_fixed_length_rain(
        &self,
        sk: &MAYOSkType,
        m: &MAYOMessageType,
    ) -> MAYOSignatureType {
        let mut sig_len = 0; // not important for us
        let mut sig = vec![0; self.mayo_params.sig_bytes];

        assert_eq!(MAYO_OK, unsafe {
            crate::mayo_rain_sign_fixed_length_input(
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
    /// use mayo_c_rain_sys::mayo::*;
    /// use mayo_c_rain_sys::mayo::MAYOParameterSet;
    ///
    /// // initialize with MAYO_1 parameters
    /// let mayo1 = MAYO::setup(MAYOParameterSet::MAYO1);
    /// // generate the keys
    /// let (pk, sk) = mayo1.keygen();
    ///
    /// let m = vec![0; mayo1.mayo_params.m_digest_bytes];
    ///
    /// let sig = mayo1.sign_fixed_length_rain(&sk, &m);
    ///
    /// assert!(mayo1.verify_fixed_length_rain(&pk, &m, &sig));
    /// ```
    pub fn verify_fixed_length_rain(
        &self,
        pk: &MAYOPkType,
        m: &MAYOMessageType,
        sig: &MAYOSignatureType,
    ) -> bool {
        MAYO_OK
            == unsafe {
                crate::mayo_rain_verify_fixed_length_input(
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
mod test_mayo_rainhash {
    use crate::mayo::{MAYO, MAYOParameterSet};

    #[test]
    fn mayo_sign_rain() {
        // initialize with MAYO_1 parameters
        let mayo1 = MAYO::setup(MAYOParameterSet::MAYO1);
        // generate the keys
        let (pk, sk) = mayo1.keygen();

        let m = vec![42; mayo1.mayo_params.m_digest_bytes];

        let sig = mayo1.sign_fixed_length_rain(&sk, &m);

        assert!(mayo1.verify_fixed_length_rain(&pk, &m, &sig));
    }
}
