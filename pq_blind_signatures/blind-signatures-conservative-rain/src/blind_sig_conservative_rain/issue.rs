extern crate rand;
use super::{presig_message, NibsLowmc, NonceType, PresignatureType, RecipientPkType, SkType};
use crate::derive::NONCE_BYTES;
use rand::Rng;

impl NibsLowmc {
    pub fn issue(
        &self,
        sk: &SkType,
        pk_r: &RecipientPkType,
    ) -> (PresignatureType, NonceType) {
        let mut rng = rand::rng();
        let nonce: NonceType = (0..NONCE_BYTES).map(|_| rng.random()).collect();
        let msg = presig_message(pk_r, &nonce);
        let presig = self.mayo.sign_fixed_length_rain(sk, &msg);
        (presig, nonce)
    }
}
