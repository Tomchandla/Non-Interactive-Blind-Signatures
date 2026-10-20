//! Parameter selection: which NIBS construction, which MAYO mode, and which
//! VOLEitH parameter set (which fixes the NIST level).

use std::fmt;

/// How the receiver public key binds the receiver's LowMC key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Framework {
    /// Baldimtsi et al. (ASIACRYPT'24) generic construction:
    /// `pk_R = RainHash(op || K)`, `m = LowMC_K(r)`.
    Bcgy,
    /// sPRP framework (Sec. 5.2 of the paper), with the fixed-input key
    /// commitment `pk_R = LowMC_K(0||c0) || LowMC_K(0||c1)` and
    /// `m = LowMC_K(1||r)`.
    Sprp,
}

/// How MAYO signs `M = r || pk_R`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MayoMode {
    /// MAYO with salt: target `T(r || pk_R || salt)`; presignature `s || salt`.
    Standard,
    /// One-More-MAYO (Baum et al., USENIX'26): preimage of `T(r || pk_R)`, no
    /// salt. Security rests on one-more preimage resistance of the MAYO map.
    OneMore,
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
    pub mayo_mode: MayoMode,
    pub zk: ZKType,
}

impl NibsParams {
    pub const fn new(framework: Framework, mayo_mode: MayoMode, zk: ZKType) -> Self {
        Self { framework, mayo_mode, zk }
    }

    /// Variant id understood by the C library (`NIBS_VARIANT_*`).
    pub fn variant_id(&self) -> u32 {
        match (self.framework, self.mayo_mode) {
            (Framework::Bcgy, MayoMode::Standard) => 0,
            (Framework::Bcgy, MayoMode::OneMore) => 1,
            (Framework::Sprp, MayoMode::Standard) => 2,
            (Framework::Sprp, MayoMode::OneMore) => 3,
        }
    }

    pub fn is_sprp(&self) -> bool {
        self.framework == Framework::Sprp
    }

    pub fn is_one_more(&self) -> bool {
        self.mayo_mode == MayoMode::OneMore
    }

    /// Short label, e.g. `BCGY+MAYO` or `sPRP+OMM`.
    pub fn variant_label(&self) -> &'static str {
        match (self.framework, self.mayo_mode) {
            (Framework::Bcgy, MayoMode::Standard) => "BCGY+MAYO",
            (Framework::Bcgy, MayoMode::OneMore) => "BCGY+OMM",
            (Framework::Sprp, MayoMode::Standard) => "sPRP+MAYO",
            (Framework::Sprp, MayoMode::OneMore) => "sPRP+OMM",
        }
    }

    /// Every variant for one VOLEitH parameter set.
    pub fn variants(zk: ZKType) -> [NibsParams; 4] {
        [
            NibsParams::new(Framework::Bcgy, MayoMode::Standard, zk),
            NibsParams::new(Framework::Bcgy, MayoMode::OneMore, zk),
            NibsParams::new(Framework::Sprp, MayoMode::Standard, zk),
            NibsParams::new(Framework::Sprp, MayoMode::OneMore, zk),
        ]
    }

    /// All 48 instances.
    pub fn all() -> Vec<NibsParams> {
        ZKType::ALL.iter().flat_map(|&z| NibsParams::variants(z)).collect()
    }
}

impl fmt::Display for NibsParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.variant_label(), self.zk.name())
    }
}
