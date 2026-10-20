#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

//! Raw bindings to the NIBS VOLEitH library (`libconsv_bs_rainhash`).
//! See `vole/conservative_bs/faest.h` for the C interface.

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod lowmc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_instance_reports_sizes() {
        for variant in 0..4u32 {
            for level in [1u32, 3, 5] {
                for speed in 0..2u32 {
                    for version in 1..=2u32 {
                        let mut info: nibs_instance_info = unsafe { std::mem::zeroed() };
                        assert!(unsafe {
                            nibs_instance_info_get(variant, level, speed, version, &mut info)
                        });
                        assert!(info.proof_bytes > 0);
                        assert_eq!(info.random_seed_bytes as u32 * 8, [128, 192, 256][(level / 2) as usize]);
                    }
                }
            }
        }
        let mut info: nibs_instance_info = unsafe { std::mem::zeroed() };
        assert!(!unsafe { nibs_instance_info_get(4, 1, 0, 1, &mut info) });
    }
}
