//! Thin wrapper around the VOLEitH prover/verifier of the C++ library.

use crate::params::NibsParams;
use vole_rainhash_then_mayo_sys::{nibs_instance_info, nibs_instance_info_get, nibs_prove, nibs_verify};

/// Sizes and counts for one instance, as reported by the circuit library.
pub type InstanceInfo = nibs_instance_info;

pub fn instance_info(p: &NibsParams) -> InstanceInfo {
    let mut info: InstanceInfo = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        nibs_instance_info_get(p.variant_id(), p.zk.level(), p.zk.speed(), p.zk.version(), &mut info)
    };
    assert!(ok, "instance {p} is not compiled into the circuit library");
    info
}

/// Secrets for one proof (byte strings in the sizes of [`InstanceInfo`]).
pub struct Witness<'a> {
    pub s: &'a [u8],
    pub key: &'a [u8],
    pub opening: &'a [u8],
    pub nonce: &'a [u8],
    pub salt: &'a [u8],
}

#[allow(clippy::too_many_arguments)]
pub fn prove(
    p: &NibsParams,
    info: &InstanceInfo,
    random_seed: &[u8],
    expanded_pk: &[u8],
    m: &[u8],
    w: &Witness<'_>,
    fs_context: &[u8; 32],
) -> Vec<u8> {
    assert_eq!(expanded_pk.len(), info.expanded_pk_bytes);
    assert_eq!(m.len(), info.m_bytes);
    assert_eq!(w.s.len(), info.s_bytes);
    assert_eq!(w.key.len(), info.k_bytes);
    assert_eq!(w.nonce.len(), info.r_bytes);
    assert_eq!(w.opening.len(), info.op_bytes);
    assert_eq!(w.salt.len(), info.salt_bytes);
    let mut proof = vec![0u8; info.proof_bytes];
    let ok = unsafe {
        nibs_prove(
            p.variant_id(),
            p.zk.level(),
            p.zk.speed(),
            p.zk.version(),
            proof.as_mut_ptr(),
            proof.len(),
            random_seed.as_ptr(),
            random_seed.len(),
            expanded_pk.as_ptr(),
            m.as_ptr(),
            w.s.as_ptr(),
            w.key.as_ptr(),
            w.opening.as_ptr(),
            w.nonce.as_ptr(),
            w.salt.as_ptr(),
            fs_context.as_ptr(),
        )
    };
    assert!(ok, "VOLEitH prover failed for {p}");
    proof
}

pub fn verify(
    p: &NibsParams,
    proof: &[u8],
    expanded_pk: &[u8],
    m: &[u8],
    fs_context: &[u8; 32],
) -> bool {
    unsafe {
        nibs_verify(
            p.variant_id(),
            p.zk.level(),
            p.zk.speed(),
            p.zk.version(),
            proof.as_ptr(),
            proof.len(),
            expanded_pk.as_ptr(),
            m.as_ptr(),
            fs_context.as_ptr(),
        )
    }
}

/// Testing aid: evaluate the circuit on the witness built from `w` (with one
/// witness bit flipped if `flip_bit` is `Some`) and return the number of
/// unsatisfied constraints. `None` if the instance or bit index is invalid.
pub fn count_unsatisfied(
    p: &NibsParams,
    expanded_pk: &[u8],
    m: &[u8],
    w: &Witness<'_>,
    flip_bit: Option<usize>,
) -> Option<usize> {
    let r = unsafe {
        vole_rainhash_then_mayo_sys::nibs_count_unsatisfied(
            p.variant_id(),
            p.zk.level(),
            p.zk.speed(),
            p.zk.version(),
            expanded_pk.as_ptr(),
            m.as_ptr(),
            w.s.as_ptr(),
            w.key.as_ptr(),
            w.opening.as_ptr(),
            w.nonce.as_ptr(),
            w.salt.as_ptr(),
            flip_bit.unwrap_or(usize::MAX),
        )
    };
    (r != usize::MAX).then_some(r)
}
