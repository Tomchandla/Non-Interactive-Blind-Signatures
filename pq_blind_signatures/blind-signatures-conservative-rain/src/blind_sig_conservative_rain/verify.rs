use super::{DerivedMessageType, NibsLowmc, SignatureType};

impl NibsLowmc {
    /// Publicly verifies the blind signature. m is the derived 32-byte
    /// message, bound into the circuit as the public value that gadget
    /// GadM's output must equal. NOTE: unlike the interactive scheme there
    /// is no SHAKE256 pre-hash of an arbitrary message here -- m IS the
    /// message, fixed length by construction.
    ///
    /// # Parameters
    /// - `epk`: the expanded MAYO public key
    /// - `m`: the message
    /// - `sig`: the signature, i.e., the zk proof
    pub fn verify(
        &self,
        epk: &mut [u8],
        m: &DerivedMessageType,
        sig: &mut SignatureType,
        additional_r: &mut [u8],
    ) -> bool {
        let mut m = m.clone();
        self.vole_rain_then_mayo
            .verify(sig, epk, &mut m, additional_r)
    }
}
