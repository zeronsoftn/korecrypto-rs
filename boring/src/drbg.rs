//! Deterministic random bit generators (SP 800-90A): Hash_DRBG and HMAC_DRBG.
//!
//! These are KCMVP validation-target DRBGs. The caller supplies the entropy
//! input and nonce; the generators do not gather entropy themselves. (CTR_DRBG
//! is available through BoringSSL's `ctrdrbg` interface.)

use std::mem::MaybeUninit;

use crate::error::ErrorStack;
use crate::ffi;
use crate::hash::MessageDigest;

fn opt(slice: &[u8]) -> (*const u8, usize) {
    (slice.as_ptr(), slice.len())
}

/// Hash_DRBG (SP 800-90A).
pub struct HashDrbg(ffi::HASH_DRBG);

impl HashDrbg {
    /// Instantiates a Hash_DRBG over `md` with the given entropy, nonce, and
    /// personalization string.
    pub fn new(
        md: MessageDigest,
        entropy: &[u8],
        nonce: &[u8],
        perso: &[u8],
    ) -> Result<Self, ErrorStack> {
        crate::ffi::init();
        let mut st = MaybeUninit::<ffi::HASH_DRBG>::uninit();
        let (pp, pl) = opt(perso);
        let ok = unsafe {
            ffi::HASH_DRBG_init(
                st.as_mut_ptr(),
                md.as_ptr(),
                entropy.as_ptr(),
                entropy.len(),
                nonce.as_ptr(),
                nonce.len(),
                pp,
                pl,
            )
        };
        if ok == 1 {
            Ok(HashDrbg(unsafe { st.assume_init() }))
        } else {
            Err(ErrorStack::get())
        }
    }

    /// Reseeds with fresh entropy and optional additional input.
    pub fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> Result<(), ErrorStack> {
        let (ap, al) = opt(addtl);
        let ok =
            unsafe { ffi::HASH_DRBG_reseed(&mut self.0, entropy.as_ptr(), entropy.len(), ap, al) };
        if ok == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }

    /// Fills `out` with pseudorandom bytes, with optional additional input.
    pub fn generate(&mut self, out: &mut [u8], addtl: &[u8]) -> Result<(), ErrorStack> {
        let (ap, al) = opt(addtl);
        let ok =
            unsafe { ffi::HASH_DRBG_generate(&mut self.0, out.as_mut_ptr(), out.len(), ap, al) };
        if ok == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }
}

/// HMAC_DRBG (SP 800-90A).
pub struct HmacDrbg(ffi::HMAC_DRBG);

impl HmacDrbg {
    /// Instantiates an HMAC_DRBG over `md` with the given entropy, nonce, and
    /// personalization string.
    pub fn new(
        md: MessageDigest,
        entropy: &[u8],
        nonce: &[u8],
        perso: &[u8],
    ) -> Result<Self, ErrorStack> {
        crate::ffi::init();
        let mut st = MaybeUninit::<ffi::HMAC_DRBG>::uninit();
        let (pp, pl) = opt(perso);
        let ok = unsafe {
            ffi::HMAC_DRBG_init(
                st.as_mut_ptr(),
                md.as_ptr(),
                entropy.as_ptr(),
                entropy.len(),
                nonce.as_ptr(),
                nonce.len(),
                pp,
                pl,
            )
        };
        if ok == 1 {
            Ok(HmacDrbg(unsafe { st.assume_init() }))
        } else {
            Err(ErrorStack::get())
        }
    }

    /// Reseeds with fresh entropy and optional additional input.
    pub fn reseed(&mut self, entropy: &[u8], addtl: &[u8]) -> Result<(), ErrorStack> {
        let (ap, al) = opt(addtl);
        let ok =
            unsafe { ffi::HMAC_DRBG_reseed(&mut self.0, entropy.as_ptr(), entropy.len(), ap, al) };
        if ok == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }

    /// Fills `out` with pseudorandom bytes, with optional additional input.
    pub fn generate(&mut self, out: &mut [u8], addtl: &[u8]) -> Result<(), ErrorStack> {
        let (ap, al) = opt(addtl);
        let ok =
            unsafe { ffi::HMAC_DRBG_generate(&mut self.0, out.as_mut_ptr(), out.len(), ap, al) };
        if ok == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    // NIST CAVP convention: instantiate, generate (discard), generate (compare).
    #[test]
    fn hash_drbg_sha256_kat() {
        let entropy =
            Vec::from_hex("a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb")
                .unwrap();
        let nonce = Vec::from_hex("8581f9317517276e06e9607ddbcbcc2e").unwrap();
        let expected = Vec::from_hex(
            "d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80daaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df",
        )
        .unwrap();

        let mut drbg = HashDrbg::new(MessageDigest::sha256(), &entropy, &nonce, &[]).unwrap();
        let mut out = vec![0u8; expected.len()];
        drbg.generate(&mut out, &[]).unwrap();
        drbg.generate(&mut out, &[]).unwrap();
        assert_eq!(out, expected, "Hash_DRBG mismatch");
    }

    #[test]
    fn hmac_drbg_sha256_kat() {
        let entropy =
            Vec::from_hex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488")
                .unwrap();
        let nonce = Vec::from_hex("659ba96c601dc69fc902940805ec0ca8").unwrap();
        let expected = Vec::from_hex(
            "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
        )
        .unwrap();

        let mut drbg = HmacDrbg::new(MessageDigest::sha256(), &entropy, &nonce, &[]).unwrap();
        let mut out = vec![0u8; expected.len()];
        drbg.generate(&mut out, &[]).unwrap();
        drbg.generate(&mut out, &[]).unwrap();
        assert_eq!(out, expected, "HMAC_DRBG mismatch");
    }
}
