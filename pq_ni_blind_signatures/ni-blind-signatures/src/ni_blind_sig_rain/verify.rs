use super::{DerivedMessageType, NibsLowmc, SignatureType};

impl NibsLowmc {
    pub fn verify(
        &self,
        epk: &mut [u8],
        m: &DerivedMessageType,
        sig: &mut SignatureType,
        additional_r: &mut [u8],
    ) -> bool {
        let mut m = m.clone();
        self.vole_rain_then_mayo.verify(sig, epk, &mut m, additional_r)
    }
}
