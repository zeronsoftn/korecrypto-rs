//! KCMVP 검증대상 블록암호 스트림 운영모드(OFB / CFB).
//!
//! AES/ARIA/LEA/SEED/HIGHT 블록암호 위의 OFB·CFB 모드 로직은 라이브러리(검증
//! 경계) 안(`crypto/fipsmodule/cipher/kcmvp_modes.cc.inc`)에 있고, 여기서는 그
//! C 함수(`KCMVP_ofb_crypt` / `KCMVP_cfb_crypt`)를 안전하게 감싼다. CFB 는
//! 피드백 폭을 비트 단위(1/8/32/64/128)로 지정할 수 있다.
//!
//! `iv` 는 불변 참조로 받는다(내부에서 복사해 C 에 전달). 호출자는 갱신된
//! 레지스터 상태가 필요 없다(MCT 는 하네스에서 별도로 처리).

use crate::error::ErrorStack;
use crate::ffi;

/// 하부 블록암호 종류(C 의 `KCMVP_CIPHER_*` 와 값이 같다).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockCipher {
    Aes = 0,
    Aria = 1,
    Lea = 2,
    Seed = 3,
    Hight = 4,
}

impl BlockCipher {
    /// 블록 길이(바이트). HIGHT 만 8, 나머지는 16.
    #[must_use]
    pub fn block_len(self) -> usize {
        if self == BlockCipher::Hight {
            8
        } else {
            16
        }
    }
}

/// OFB 모드로 `input` 을 변환한다(암/복호 동일). `iv` 는 블록 길이의 피드백
/// 레지스터 초기값이며, 내부 복사본으로만 사용된다.
pub fn ofb_crypt(
    cipher: BlockCipher,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    crate::ffi::init();
    let mut iv_buf = iv.to_vec();
    let mut out = vec![0u8; input.len()];
    let ok = unsafe {
        ffi::KCMVP_ofb_crypt(
            cipher as i32,
            key.as_ptr(),
            key.len(),
            iv_buf.as_mut_ptr(),
            input.as_ptr(),
            out.as_mut_ptr(),
            input.len(),
        )
    };
    if ok == 1 {
        Ok(out)
    } else {
        Err(ErrorStack::get())
    }
}

/// CFB 모드로 `total_bits` 비트를 변환한다. `feedback_bits` 는 피드백 폭(블록
/// 비트 이하, `total_bits` 의 약수). 입출력은 MSB-first 로 패킹된 비트열이며,
/// 반환 벡터 길이는 `ceil(total_bits/8)`. `iv` 는 내부 복사본으로만 사용된다.
pub fn cfb_crypt(
    cipher: BlockCipher,
    key: &[u8],
    iv: &[u8],
    feedback_bits: u32,
    input: &[u8],
    total_bits: usize,
    encrypt: bool,
) -> Result<Vec<u8>, ErrorStack> {
    crate::ffi::init();
    let mut iv_buf = iv.to_vec();
    let out_len = total_bits.div_ceil(8);
    let mut out = vec![0u8; out_len];
    let ok = unsafe {
        ffi::KCMVP_cfb_crypt(
            cipher as i32,
            key.as_ptr(),
            key.len(),
            iv_buf.as_mut_ptr(),
            feedback_bits,
            input.as_ptr(),
            out.as_mut_ptr(),
            total_bits,
            encrypt as i32,
        )
    };
    if ok == 1 {
        Ok(out)
    } else {
        Err(ErrorStack::get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    // NIST SP 800-38A AES-128 OFB, F.4.1 첫 블록.
    #[test]
    fn aes128_ofb_kat() {
        let key = Vec::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = Vec::from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ct = Vec::from_hex("3b3fd92eb72dad20333449f8e83cfb4a").unwrap();
        let out = ofb_crypt(BlockCipher::Aes, &key, &iv, &pt).unwrap();
        assert_eq!(out, ct, "AES-128 OFB mismatch");
    }

    // NIST SP 800-38A AES-128 CFB128 (F.3.13/F.3.14) 2블록 절대값.
    #[test]
    fn aes128_cfb128_kat() {
        let key = Vec::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = Vec::from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
            .unwrap();
        let ct = Vec::from_hex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b")
            .unwrap();
        let out = cfb_crypt(BlockCipher::Aes, &key, &iv, 128, &pt, 256, true).unwrap();
        assert_eq!(out, ct, "AES-128 CFB128 encrypt mismatch");
        let back = cfb_crypt(BlockCipher::Aes, &key, &iv, 128, &ct, 256, false).unwrap();
        assert_eq!(back, pt, "AES-128 CFB128 decrypt mismatch");
    }

    // CFB8 왕복(HIGHT, 8바이트 블록).
    #[test]
    fn hight_cfb8_roundtrip() {
        let key = Vec::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let iv = Vec::from_hex("8000000000000000").unwrap();
        let pt = Vec::from_hex("1a93e8").unwrap();
        let ct = cfb_crypt(BlockCipher::Hight, &key, &iv, 8, &pt, 24, true).unwrap();
        let back = cfb_crypt(BlockCipher::Hight, &key, &iv, 8, &ct, 24, false).unwrap();
        assert_eq!(back, pt, "HIGHT CFB8 roundtrip mismatch");
    }
}
