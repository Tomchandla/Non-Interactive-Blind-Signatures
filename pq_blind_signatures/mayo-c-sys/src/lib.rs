#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod mayo;

#[cfg(test)]
mod test_mayo_loop {
    use crate::{
        CPK_BYTES_MAX, CSK_BYTES_MAX, MAYO_5, MAYO_OK, SIG_BYTES_MAX, mayo_keypair, mayo_sign,
        mayo_verify,
    };

    fn MAYO_keygen() -> ([u8; CPK_BYTES_MAX as usize], [u8; CSK_BYTES_MAX as usize]) {
        let mut pk: [u8; CPK_BYTES_MAX as usize] = [0; CPK_BYTES_MAX as usize];
        let mut sk: [u8; CSK_BYTES_MAX as usize] = [0; CSK_BYTES_MAX as usize];

        assert_eq!(MAYO_OK, unsafe {
            mayo_keypair(&MAYO_5, pk.as_mut_ptr(), sk.as_mut_ptr())
                .try_into()
                .unwrap()
        });
        (pk, sk)
    }

    fn MAYO_sign(
        sk: &[u8; CSK_BYTES_MAX as usize],
        message: &[u8; 32],
    ) -> [u8; SIG_BYTES_MAX as usize + 32] {
        let mut sig = [0; SIG_BYTES_MAX as usize + 32];
        unsafe {
            mayo_sign(
                &MAYO_5,
                sig.as_mut_ptr(),
                &mut (SIG_BYTES_MAX as usize + 32),
                message.as_ptr(),
                message.len(),
                sk.as_ptr(),
            )
        };
        sig
    }

    fn MAYO_verify(
        pk: &[u8; CPK_BYTES_MAX as usize],
        message: &[u8; 32],
        signature: &[u8; SIG_BYTES_MAX as usize + 32],
    ) -> bool {
        0 == unsafe {
            mayo_verify(
                &MAYO_5,
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                pk.as_ptr(),
            )
        }
    }

    /// Make a simple test consisting of:
    /// 1. Generating a set of public key and verification key
    /// 2. Generating a signature
    /// 3. Verifying that the signature is valid
    ///
    /// Each of them using the functions provided by MAYO
    #[test]
    fn example() {
        let (pk, sk) = MAYO_keygen();
        let mut message = [0; 32];
        message[0] = 42;
        let signature = MAYO_sign(&sk, &message);

        assert!(MAYO_verify(&pk, &message, &signature))
    }
}
