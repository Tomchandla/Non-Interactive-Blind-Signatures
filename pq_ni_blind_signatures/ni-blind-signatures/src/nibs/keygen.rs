use super::{Nibs, PkType, RecipientPkType, RecipientSk, SkType};
use rand::Rng;
use vole_rainhash_then_mayo_sys::lowmc;

impl Nibs {
    /// KeyGen_S: a MAYO key pair. The verification key is the compressed pk.
    pub fn keygen_signer(&self) -> (PkType, SkType) {
        self.mayo.keygen()
    }

    /// KeyGen_R: sample K (and op for BCGY) and derive pk_R.
    pub fn keygen_recipient(&self) -> (RecipientPkType, RecipientSk) {
        let mut rng = rand::rng();
        let key: Vec<u8> = (0..self.info.k_bytes).map(|_| rng.random()).collect();
        let opening: Vec<u8> = (0..self.info.op_bytes).map(|_| rng.random()).collect();
        let sk = RecipientSk { key, opening };
        (self.derive_pkr(&sk), sk)
    }

    /// pk_R from the receiver secret (the same function the circuit proves).
    pub fn derive_pkr(&self, sk: &RecipientSk) -> RecipientPkType {
        assert_eq!(sk.key.len(), self.info.k_bytes);
        assert_eq!(sk.opening.len(), self.info.op_bytes);
        let dummy = [0u8; 32];
        let op: &[u8] = if sk.opening.is_empty() { &dummy } else { &sk.opening };
        lowmc::derive_pkr(self.params.variant_id(), self.level(), &sk.key, op, self.info.pkr_bytes)
    }

    /// m from K and the nonce (the same function the circuit proves).
    pub fn derive_message(&self, key: &[u8], nonce: &[u8]) -> Vec<u8> {
        assert_eq!(key.len(), self.info.k_bytes);
        assert_eq!(nonce.len(), self.info.r_bytes);
        lowmc::derive_message(self.params.variant_id(), self.level(), key, nonce)
    }
}
