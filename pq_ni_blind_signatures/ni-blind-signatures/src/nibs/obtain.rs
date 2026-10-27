use super::{MessageType, Nibs, NonceType, PkType, PresignatureType, RecipientSk, Signature};
use crate::zk::{self, Witness};
use rand::Rng;

impl Nibs {
    /// Obtain: returns None (the scheme's ⊥) if the presignature does not
    /// verify for M (see `presig_message`); otherwise derives m and proves the relation.
    ///
    /// `epk` is the signer's expanded MAYO key (`expand_pk(pk)`), which the
    /// receiver can cache across obtains.
    pub fn obtain(
        &self,
        pk: &PkType,
        epk: &[u8],
        sk_r: &RecipientSk,
        presig: &PresignatureType,
        nonce: &NonceType,
    ) -> Option<(MessageType, Signature)> {
        if nonce.len() != self.info.r_bytes || presig.len() != self.presignature_bytes() {
            return None;
        }
        let pk_r = self.derive_pkr(sk_r);
        let msg = self.presig_message(&pk_r, nonce);
        if !self.mayo.verify_nibs(pk, &msg, presig) {
            return None;
        }

        let (s, salt) = presig.split_at(self.info.s_bytes);
        let m = self.derive_message(&sk_r.key, nonce);

        let mut rng = rand::rng();
        let seed: Vec<u8> = (0..self.info.random_seed_bytes).map(|_| rng.random()).collect();
        let fs = self.fs_context(pk, &m);
        let w = Witness { s, key: &sk_r.key, opening: &sk_r.opening, nonce, salt };
        let proof = zk::prove(&self.params, &self.info, &seed, epk, &m, &w, &fs);
        Some((m, Signature { proof }))
    }
}
