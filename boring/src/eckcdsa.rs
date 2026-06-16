//! EC-KCDSA (타원곡선 한국형 전자서명, TTAK.KO-12.0015).
//!
//! KCMVP 검증대상 전자서명. NIST 소수체 곡선(P-224, P-256)과 일치하는 해시
//! (SHA-224/SHA-256)를 사용한다. 공개키는 Q = (d^{-1} mod n)·G 로 정의된다.

use crate::error::ErrorStack;
use crate::ffi;
use crate::hash::MessageDigest;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_KCDSA_KEY;
    fn drop = ffi::EC_KCDSA_KEY_free;

    /// EC-KCDSA 키(도메인 파라미터 + 키 쌍).
    pub struct EcKcdsaKey;
}

impl EcKcdsaKey {
    /// 곡선 NID(P-224: `NID_secp224r1`, P-256: `NID_X9_62_prime256v1`)로 빈 키를
    /// 생성한다.
    pub fn new(nid: i32) -> Result<Self, ErrorStack> {
        crate::ffi::init();
        unsafe {
            let ptr = ffi::EC_KCDSA_KEY_new(nid);
            if ptr.is_null() {
                Err(ErrorStack::get())
            } else {
                Ok(EcKcdsaKey::from_ptr(ptr))
            }
        }
    }

    /// 개인키 d(빅엔디안)를 설정하고 공개키 Q = d^{-1}·G 를 계산한다.
    pub fn set_private(&mut self, d: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::EC_KCDSA_KEY_set_private(self.as_ptr(), d.as_ptr(), d.len()) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// 검증용으로 공개키 좌표(빅엔디안)를 설정한다.
    pub fn set_public(&mut self, qx: &[u8], qy: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::EC_KCDSA_KEY_set_public(
                self.as_ptr(),
                qx.as_ptr(),
                qx.len(),
                qy.as_ptr(),
                qy.len(),
            ) == 1
            {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }
}

impl EcKcdsaKeyRef {
    /// 곡선 좌표/서명요소 바이트 길이 L(서명 길이는 2L).
    pub fn coord_len(&self) -> usize {
        unsafe { ffi::EC_KCDSA_coord_len(self.as_ptr()) }
    }

    /// 공개키 좌표(각 L바이트, 빅엔디안)를 추출한다.
    pub fn public_coords(&self) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        let l = self.coord_len();
        let mut qx = vec![0u8; l];
        let mut qy = vec![0u8; l];
        unsafe {
            if ffi::EC_KCDSA_KEY_get_public(self.as_ptr(), qx.as_mut_ptr(), qy.as_mut_ptr(), l) == 1
            {
                Ok((qx, qy))
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// `msg` 에 서명한다. `k` 가 `Some` 이면 그 난수(빅엔디안)를 사용하고,
    /// `None` 이면 내부 난수를 생성한다.
    pub fn sign(
        &self,
        md: MessageDigest,
        msg: &[u8],
        k: Option<&[u8]>,
    ) -> Result<Vec<u8>, ErrorStack> {
        let mut sig = vec![0u8; 2 * self.coord_len()];
        let mut sig_len = 0usize;
        let (kp, kl) = match k {
            Some(k) => (k.as_ptr(), k.len()),
            None => (ptr::null(), 0),
        };
        unsafe {
            if ffi::EC_KCDSA_sign(
                self.as_ptr(),
                md.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                kp,
                kl,
                sig.as_mut_ptr(),
                &mut sig_len,
            ) == 1
            {
                sig.truncate(sig_len);
                Ok(sig)
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// 서명을 검증한다.
    pub fn verify(&self, md: MessageDigest, msg: &[u8], sig: &[u8]) -> bool {
        unsafe {
            ffi::EC_KCDSA_verify(
                self.as_ptr(),
                md.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
            ) == 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nid::Nid;
    use hex::FromHex;

    // KISA EC-KCDSA 참조구현(SECP224r1 / SHA-224) 교차검증 KAT.
    #[test]
    fn eckcdsa_p224_sha224_kat() {
        let d = Vec::from_hex("d64d9dd6c42dc192b1f7e27d07d7a440ec57e63f5912551fbc9db763").unwrap();
        let qx = Vec::from_hex("e9d6260a4fb11ecb60906e4537d6f0e58ebdc66f41d4a522f7231b54").unwrap();
        let qy = Vec::from_hex("a2bcd7dd6485de0696787a2330c18ec71c8fcfdcfea0349d971c2172").unwrap();
        let k = Vec::from_hex("c7f4256009f44d85f6cd6fd70dacc3073b5ab4a7685005f82cd1f110").unwrap();
        let msg = Vec::from_hex(
            "5468697320697320612073616d706c65206d65737361676520666f722045432d4b4344534120696d706c656d656e746174696f6e2076616c69646174696f6e2e",
        )
        .unwrap();
        let expected_r =
            Vec::from_hex("fd17390ea6100ae380fd779f61f774e529305ff2937a1303cfad70cf").unwrap();
        let expected_s =
            Vec::from_hex("c06e733348347c5bc735930d1bb0c0a557c01de9ca1a85c2081c66e5").unwrap();

        let mut key = EcKcdsaKey::new(Nid::SECP224R1.as_raw()).unwrap();
        key.set_private(&d).unwrap();

        // 공개키 Q = d^{-1}·G 가 참조구현과 일치하는지 확인.
        let (gx, gy) = key.public_coords().unwrap();
        assert_eq!(gx, qx, "Qx mismatch");
        assert_eq!(gy, qy, "Qy mismatch");

        // 서명이 참조 벡터와 정확히 일치하는지 확인.
        let sig = key.sign(MessageDigest::sha224(), &msg, Some(&k)).unwrap();
        let mut expected = expected_r.clone();
        expected.extend_from_slice(&expected_s);
        assert_eq!(sig, expected, "signature mismatch");

        // 검증 성공.
        assert!(key.verify(MessageDigest::sha224(), &msg, &sig));

        // 메시지 변조 시 검증 실패.
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert!(!key.verify(MessageDigest::sha224(), &bad, &sig));
    }

    // 공개키만으로(검증자 입장) 검증되는지 확인.
    #[test]
    fn eckcdsa_verify_with_public_only() {
        let qx = Vec::from_hex("e9d6260a4fb11ecb60906e4537d6f0e58ebdc66f41d4a522f7231b54").unwrap();
        let qy = Vec::from_hex("a2bcd7dd6485de0696787a2330c18ec71c8fcfdcfea0349d971c2172").unwrap();
        let msg = Vec::from_hex(
            "5468697320697320612073616d706c65206d65737361676520666f722045432d4b4344534120696d706c656d656e746174696f6e2076616c69646174696f6e2e",
        )
        .unwrap();
        let mut sig =
            Vec::from_hex("fd17390ea6100ae380fd779f61f774e529305ff2937a1303cfad70cf").unwrap();
        sig.extend_from_slice(
            &Vec::from_hex("c06e733348347c5bc735930d1bb0c0a557c01de9ca1a85c2081c66e5").unwrap(),
        );

        let mut key = EcKcdsaKey::new(Nid::SECP224R1.as_raw()).unwrap();
        key.set_public(&qx, &qy).unwrap();
        assert!(key.verify(MessageDigest::sha224(), &msg, &sig));
    }

    // 내부 난수 사용 시 sign→verify 왕복.
    #[test]
    fn eckcdsa_roundtrip_random_k() {
        let d = Vec::from_hex("457bea7f17ff95c8bff3201ceaed53910f38481fbe653611a91aee43").unwrap();
        let mut key = EcKcdsaKey::new(Nid::SECP224R1.as_raw()).unwrap();
        key.set_private(&d).unwrap();
        let msg = b"hello ec-kcdsa";
        let sig = key.sign(MessageDigest::sha224(), msg, None).unwrap();
        assert!(key.verify(MessageDigest::sha224(), msg, &sig));
    }
}
