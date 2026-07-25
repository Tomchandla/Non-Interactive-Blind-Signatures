extern crate rand;
use super::{NibsLowmc, NonceType, PresignatureType, RecipientPkType, SkType};
use crate::derive::{derive_com, NONCE_BYTES};
use rand::Rng;

impl NibsLowmc {
    /// Issue(sk, pkR) -> (presignature, nonce).
    ///
    /// THE non-interactive step: the signer receives NOTHING from the
    /// recipient. Per the BCGY24 syntax it samples the nonce itself (public
    /// random coins), derives com = MMO_LowMC(pkR, PT(DOM_COM, nonce)) and
    /// MAYO-signs it. sign_fixed_length_rain internally samples the MAYO
    /// salt and computes t = Rain(com | salt | 0xff-cap), then samples s
    /// with T*(s) = t.
    ///
    /// (presignature, nonce) ride together to the recipient over any one-way
    /// channel, or are precomputed offline per pkR.
    ///
    /// Operational note: both the nonce and MAYO's preimage sampling are
    /// randomized, so issuing twice on the same pkR yields two distinct
    /// (presignature, nonce) pairs and thus two distinct messages --
    /// exactly the reusability property (BCGY24 Def. 5.2). Nonce collisions
    /// across issuances happen with probability <= q^2 / 2^129 and merely
    /// duplicate a message, which the one-more counting already tolerates.
    pub fn issue(
        &self,
        sk: &SkType,
        pk_r: &RecipientPkType,
    ) -> (PresignatureType, NonceType) {
        let mut rng = rand::rng();
        let nonce: NonceType = (0..NONCE_BYTES).map(|_| rng.random()).collect();
        let com = derive_com(pk_r, &nonce);
        let presig = self.mayo.sign_fixed_length_rain(sk, &com);
        (presig, nonce)
    }
}
