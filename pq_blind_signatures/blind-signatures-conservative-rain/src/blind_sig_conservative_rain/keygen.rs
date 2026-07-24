extern crate rand;
use super::{NibsLowmc, PkType, RecipientPkType, RecipientSk, RecipientSkType, SkType};
use crate::derive::{derive_pkr, OPEN_BYTES, SKR_BYTES};
use rand::Rng;

impl NibsLowmc {
    /// KeyGenS: MAYO key generation, unchanged.
    pub fn keygen_signer(&self) -> (PkType, SkType) {
        self.mayo.keygen()
    }

    /// KeyGenR: skR = (K, s) with K a 256-bit LowMC key and s a 128-bit
    /// opening; pkR = Com(K; s) = E^PRF_K(PT(DOM_PK, s)).
    ///
    /// Note: unforgeability does not require a proof of possession on pkR
    /// (K and s are extracted from the final proofs), but if you want the
    /// honest-key model for the blindness proof to be discharged explicitly,
    /// attach a small PoP here (e.g. a VOLEitH proof of knowledge of (K, s),
    /// reusing the GadA gadget standalone) -- optional.
    pub fn keygen_recipient(&self) -> (RecipientPkType, RecipientSkType) {
        let mut rng = rand::rng();
        let key: Vec<u8> = (0..SKR_BYTES).map(|_| rng.random()).collect();
        let opening: Vec<u8> = (0..OPEN_BYTES).map(|_| rng.random()).collect();
        let pk_r = derive_pkr(&key, &opening);
        (pk_r, RecipientSk { key, opening })
    }
}
