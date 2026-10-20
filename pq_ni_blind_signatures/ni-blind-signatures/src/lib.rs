//! Post-quantum non-interactive blind signatures (NIBS) from MAYO, LowMC,
//! RainHash and VOLE-in-the-Head.
//!
//! Four variants (BCGY or sPRP framework, standard or One-More MAYO) at NIST
//! levels 1, 3 and 5; see [`params::NibsParams`].

pub mod nibs;
pub mod params;
pub mod zk;

pub use nibs::{Nibs, RecipientSk, Signature};
pub use params::{Framework, MayoMode, NibsParams, ZKType};
