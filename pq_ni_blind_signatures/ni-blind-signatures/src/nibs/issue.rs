use super::{Nibs, NonceType, PresignatureType, RecipientPkType, SkType};
use rand::Rng;

impl Nibs {
    /// Issue: fresh nonce r and a MAYO presignature on M.
    pub fn issue(&self, sk: &SkType, pk_r: &RecipientPkType) -> (PresignatureType, NonceType) {
        let mut rng = rand::rng();
        let mut nonce: NonceType = (0..self.info.r_bytes).map(|_| rng.random()).collect();
        if self.params.is_sprp() {
            *nonce.last_mut().unwrap() &= 0x7f;
        }
        let msg = self.presig_message(pk_r, &nonce);
        let presig = self.mayo.sign_nibs(sk, &msg);
        debug_assert_eq!(presig.len(), self.presignature_bytes());
        (presig, nonce)
    }
}
