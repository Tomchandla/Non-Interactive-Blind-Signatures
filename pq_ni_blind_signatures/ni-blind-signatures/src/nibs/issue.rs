use super::{Nibs, NonceType, PresignatureType, RecipientPkType, SkType};
use rand::Rng;

impl Nibs {
    /// Issue: fresh nonce r and a MAYO presignature on M (see `presig_message`).
    ///
    /// For the sPRP framework the top bit of r is the domain-separation bit
    /// of the message input 1||r, so the signer samples it as 0 (only the
    /// low lambda-1 bits are random).
    pub fn issue(&self, sk: &SkType, pk_r: &RecipientPkType) -> (PresignatureType, NonceType) {
        let mut rng = rand::rng();
        let mut nonce: NonceType = (0..self.info.r_bytes).map(|_| rng.random()).collect();
        if self.params.is_sprp() {
            *nonce.last_mut().unwrap() &= 0x7f;
        }
        let msg = self.presig_message(pk_r, &nonce);
        let presig = self.mayo.sign_nibs(sk, &msg, self.params.is_one_more());
        debug_assert_eq!(presig.len(), self.presignature_bytes());
        (presig, nonce)
    }
}
