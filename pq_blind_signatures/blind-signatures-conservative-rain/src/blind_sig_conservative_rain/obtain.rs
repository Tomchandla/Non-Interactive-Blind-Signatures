use super::{
    DerivedMessageType, NibsLowmc, NonceType, PkType, PresignatureType, RecipientSkType,
    SignatureType,
};
use crate::derive::{derive_com, derive_message, derive_pkr};

impl NibsLowmc {
    /// Obtain(skR, pk, presig, nonce) -> (m, sig); panics on a bad
    /// presignature (an aborting Obtain in the paper's syntax).
    ///
    /// Witness handed to the prover: (s, skR.key, skR.opening, nonce, salt).
    /// m is derived, not chosen, and is the PUBLIC input to the proof.
    pub fn obtain(
        &self,
        pk: &PkType,
        epk: &mut [u8],
        sk_r: &RecipientSkType,
        presig: &PresignatureType,
        nonce: &NonceType,
        additional_r: &mut [u8],
    ) -> (DerivedMessageType, SignatureType) {
        let pk_r = derive_pkr(&sk_r.key, &sk_r.opening);
        let msg = [pk_r.as_slice(), nonce.as_slice()].concat();

        // check the presignature before doing any expensive proving
        assert!(
            self.mayo.verify_fixed_length_rain(pk, &msg, presig),
            "presignature does not MAYO-verify"
        );

        let mut s = presig[..(presig.len() - self.mayo.mayo_params.salt_bytes)].to_vec();
        let mut salt = presig[(presig.len() - self.mayo.mayo_params.salt_bytes)..].to_vec();

        let mut m = derive_message(&sk_r.key, nonce);

        let mut key_w = sk_r.key.clone();
        let mut open_w = sk_r.opening.clone();
        let mut nonce_w = nonce.clone();

        let sig = self.vole_rain_then_mayo.prove(
            epk,
            &mut m,
            &mut s,
            &mut key_w,
            &mut open_w,
            &mut nonce_w,
            &mut salt,
            additional_r,
        );

        (m, sig)
    }
}
