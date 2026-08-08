extern crate rand;
use super::{NibsLowmc, PkType, RecipientPkType, RecipientSk, RecipientSkType, SkType};
use crate::derive::{derive_pkr, OPEN_BYTES, SKR_BYTES};
use rand::Rng;

impl NibsLowmc {
    pub fn keygen_signer(&self) -> (PkType, SkType) {
        self.mayo.keygen()
    }
    
    pub fn keygen_recipient(&self) -> (RecipientPkType, RecipientSkType) {
        let mut rng = rand::rng();
        let key: Vec<u8> = (0..SKR_BYTES).map(|_| rng.random()).collect();
        let opening: Vec<u8> = (0..OPEN_BYTES).map(|_| rng.random()).collect();
        let pk_r = derive_pkr(&key, &opening);
        (pk_r, RecipientSk { key, opening })
    }
}
