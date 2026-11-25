//! Parameter selection: which NIBS framework and which VOLEitH parameter set
//! (which fixes the NIST level and the MAYO parameter set).

use std::fmt;

/// How the receiver public key binds the receiver's LowMC key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Framework {
    /// Baldimtsi et al. (ASIACRYPT'24) generic construction:
    /// `pk_R = RainHash(op || K)[0 : 2 lambda]`, `m = LowMC_K(r)`.
    Bcgy,
    /// sPRP framework (Algorithm 1 of the paper): `sk_R = (K, s)`,
    /// `pk_R = LowMC_K(0||s)`, `m = LowMC_K(1||r)`.
    Sprp,
}

/// VOLEitH parameter set: s(mall)/f(ast), FAEST v1/v2, security level.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZKType {
    FV1_128,
    FV1_192,
    FV1_256,
    FV2_128,
    FV2_192,
    FV2_256,
    SV1_128,
    SV1_192,
    SV1_256,
    SV2_128,
    SV2_192,
    SV2_256,
}

impl ZKType {
    pub const ALL: [ZKType; 12] = [
        ZKType::SV1_128,
        ZKType::SV2_128,
        ZKType::FV1_128,
        ZKType::FV2_128,
        ZKType::SV1_192,
        ZKType::SV2_192,
        ZKType::FV1_192,
        ZKType::FV2_192,
        ZKType::SV1_256,
        ZKType::SV2_256,
        ZKType::FV1_256,
        ZKType::FV2_256,
    ];

    /// NIST level: 1, 3 or 5.
    pub fn level(self) -> u32 {
        use ZKType::*;
        match self {
            FV1_128 | FV2_128 | SV1_128 | SV2_128 => 1,
            FV1_192 | FV2_192 | SV1_192 | SV2_192 => 3,
            FV1_256 | FV2_256 | SV1_256 | SV2_256 => 5,
        }
    }

    pub fn lambda(self) -> usize {
        match self.level() {
            1 => 128,
            3 => 192,
            _ => 256,
        }
    }

    /// 0 = small ("s"), 1 = fast ("f").
    pub fn speed(self) -> u32 {
        use ZKType::*;
        match self {
            SV1_128 | SV1_192 | SV1_256 | SV2_128 | SV2_192 | SV2_256 => 0,
            _ => 1,
        }
    }

    /// FAEST parameter version, 1 or 2.
    pub fn version(self) -> u32 {
        use ZKType::*;
        match self {
            FV1_128 | FV1_192 | FV1_256 | SV1_128 | SV1_192 | SV1_256 => 1,
            _ => 2,
        }
    }

    pub fn name(self) -> &'static str {
        use ZKType::*;
        match self {
            FV1_128 => "FV1_128",
            FV1_192 => "FV1_192",
            FV1_256 => "FV1_256",
            FV2_128 => "FV2_128",
            FV2_192 => "FV2_192",
            FV2_256 => "FV2_256",
            SV1_128 => "SV1_128",
            SV1_192 => "SV1_192",
            SV1_256 => "SV1_256",
            SV2_128 => "SV2_128",
            SV2_192 => "SV2_192",
            SV2_256 => "SV2_256",
        }
    }

    pub fn from_name(s: &str) -> Option<ZKType> {
        ZKType::ALL.into_iter().find(|z| z.name().eq_ignore_ascii_case(s))
    }
}

/// A complete NIBS instantiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NibsParams {
    pub framework: Framework,
    pub zk: ZKType,
}

impl NibsParams {
    pub const fn new(framework: Framework, zk: ZKType) -> Self {
        Self { framework, zk }
    }

    /// Variant id understood by the C library (`NIBS_VARIANT_*`).
    pub fn variant_id(&self) -> u32 {
        match self.framework {
            Framework::Bcgy => 0,
            Framework::Sprp => 1,
        }
    }

    pub fn is_sprp(&self) -> bool {
        self.framework == Framework::Sprp
    }

    /// Short label: `BCGY` or `sPRP`.
    pub fn variant_label(&self) -> &'static str {
        match self.framework {
            Framework::Bcgy => "BCGY",
            Framework::Sprp => "sPRP",
        }
    }

    /// Both frameworks for one VOLEitH parameter set.
    pub fn variants(zk: ZKType) -> [NibsParams; 2] {
        [NibsParams::new(Framework::Bcgy, zk), NibsParams::new(Framework::Sprp, zk)]
    }

    /// All 24 instances.
    pub fn all() -> Vec<NibsParams> {
        ZKType::ALL.iter().flat_map(|&z| NibsParams::variants(z)).collect()
    }
}

impl fmt::Display for NibsParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.variant_label(), self.zk.name())
    }
}
