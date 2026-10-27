use super::{Nibs, PkType, RecipientPkType, RecipientSk, SkType};
use rand::Rng;
use vole_rainhash_then_mayo_sys::lowmc;

impl Nibs {
    /// KeyGen_S: a MAYO key pair. The verification key is the compressed pk.
    pub fn keygen_signer(&self) -> (PkType, SkType) {
        self.mayo.keygen()
    }

    /// KeyGen_R: sample K and op (BCGY) or K and s (sPRP), and derive pk_R.
    ///
    /// For the sPRP framework (Algorithm 1), s is drawn from {0,1}^{lambda-1}:
    /// the top bit of the block is the domain bit 0 of the input 0||s.
    pub fn keygen_recipient(&self) -> (RecipientPkType, RecipientSk) {
        let mut rng = rand::rng();
        let key: Vec<u8> = (0..self.info.k_bytes).map(|_| rng.random()).collect();
        let mut opening: Vec<u8> = (0..self.info.op_bytes).map(|_| rng.random()).collect();
        if self.params.is_sprp() {
            *opening.last_mut().unwrap() &= 0x7f;
        }
        let sk = RecipientSk { key, opening };
        (self.derive_pkr(&sk), sk)
    }

    /// pk_R from the receiver secret (the same function the circuit proves).
    pub fn derive_pkr(&self, sk: &RecipientSk) -> RecipientPkType {
        assert_eq!(sk.key.len(), self.info.k_bytes);
        assert_eq!(sk.opening.len(), self.info.op_bytes);
        lowmc::derive_pkr(self.params.variant_id(), self.level(), &sk.key, &sk.opening, self.info.pkr_bytes)
    }

    /// m from K and the nonce (the same function the circuit proves).
    pub fn derive_message(&self, key: &[u8], nonce: &[u8]) -> Vec<u8> {
        assert_eq!(key.len(), self.info.k_bytes);
        assert_eq!(nonce.len(), self.info.r_bytes);
        lowmc::derive_message(self.params.variant_id(), self.level(), key, nonce)
    }
}
