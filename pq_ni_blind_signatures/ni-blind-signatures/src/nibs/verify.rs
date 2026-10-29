use super::{MessageType, Nibs, PkType, Signature};
use crate::zk;

impl Nibs {
    /// Verify(vk, m, sigma). `epk` is the MAYO `expand_pk(pk)` (verifiers cache it
    /// per signer; it is not part of the timed verification in the benches).
    pub fn verify(&self, pk: &PkType, epk: &[u8], m: &MessageType, sig: &Signature) -> bool {
        if m.len() != self.info.m_bytes
            || epk.len() != self.info.expanded_pk_bytes
            || sig.proof.len() != self.info.proof_bytes
        {
            return false;
        }
        let fs = self.fs_context(pk, m);
        zk::verify(&self.params, &sig.proof, epk, m, &fs)
    }
}
