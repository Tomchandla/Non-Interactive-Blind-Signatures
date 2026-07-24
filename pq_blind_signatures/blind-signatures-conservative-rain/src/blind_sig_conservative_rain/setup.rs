use super::NibsLowmc;
use crate::derive::lowmc_setup;
use crate::zk::ZKType;
use crate::zk::vole_rain_then_mayo::VOLERainThenMAYO;
use mayo_c_rain_sys::mayo::{MAYO, MAYOParameterSet};

impl NibsLowmc {
    /// Initializes the blind signature and determines all the parameters for
    /// the construction. Currently only the four L1 variants are wired
    /// (fast/slow x v1/v2 over MAYO1); extend the matches for L3/L5.
    ///
    /// Also instantiates the two LowMC instances (idempotent, one-time
    /// multi-second cost -- the `pp`-generation bucket).
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative_rain::zk::ZKType;
    /// use blind_signatures_conservative_rain::blind_sig_conservative_rain::NibsLowmc;
    ///
    /// let bs = NibsLowmc::setup(ZKType::FV1_128);
    /// ```
    pub fn setup(security_level: ZKType) -> Self {
        let mayo_param = match security_level {
            ZKType::FV1_128 => MAYOParameterSet::MAYO1,
            ZKType::FV2_128 => MAYOParameterSet::MAYO1,
            ZKType::SV1_128 => MAYOParameterSet::MAYO1,
            ZKType::SV2_128 => MAYOParameterSet::MAYO1,
            _ => panic!("parameter set is not supported"),
        };
        lowmc_setup();
        Self {
            lambda: match security_level {
                ZKType::FV1_128 => 128,
                ZKType::FV2_128 => 128,
                ZKType::SV1_128 => 128,
                ZKType::SV2_128 => 128,
                _ => panic!("parameter set is not supported"),
            },
            mayo: MAYO::setup(mayo_param),
            vole_rain_then_mayo: VOLERainThenMAYO::setup(security_level),
        }
    }
}
