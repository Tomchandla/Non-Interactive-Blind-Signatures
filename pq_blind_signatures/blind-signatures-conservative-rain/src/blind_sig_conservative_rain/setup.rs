use super::NibsLowmc;
use crate::derive::lowmc_setup;
use crate::zk::ZKType;
use crate::zk::vole_rain_then_mayo::VOLERainThenMAYO;
use mayo_c_rain_sys::mayo::{MAYO, MAYOParameterSet};

// Might add more options later for security > 128 bits.
impl NibsLowmc {
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
