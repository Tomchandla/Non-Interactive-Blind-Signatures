//! Post-quantum non-interactive blind signatures (NIBS) from MAYO, LowMC,
//! RainHash and VOLE-in-the-Head.
//!
//! Two frameworks (BCGY and sPRP) at NIST levels 1, 3 and 5, each with the
//! small and fast FAEST v1/v2 VOLEitH parameter sets; see
//! [`params::NibsParams`].

pub mod nibs;
pub mod params;
pub mod zk;

pub use nibs::{Nibs, RecipientSk, Signature};
pub use params::{Framework, NibsParams, ZKType};
