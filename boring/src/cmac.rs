//! CMAC (블록암호 기반 메시지 인증, NIST SP 800-38B / KS).
//!
//! 블록암호의 CBC 변형 `Cipher` 를 PRF 로 사용한다(AES·ARIA·SEED·LEA·HIGHT).

use std::ptr;

use crate::cvt;
use crate::error::ErrorStack;
use crate::ffi;
use crate::symm::Cipher;

/// `cipher`(블록암호 CBC 변형)와 `key` 로 `data` 의 CMAC 태그(블록 길이)를
/// 계산한다. 반환 길이는 블록 크기(AES/ARIA/SEED/LEA 16, HIGHT 8).
pub fn cmac(cipher: Cipher, key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    ffi::init();
    unsafe {
        let ctx = ffi::CMAC_CTX_new();
        if ctx.is_null() {
            return Err(ErrorStack::get());
        }
        let result = (|| -> Result<Vec<u8>, ErrorStack> {
            cvt(ffi::CMAC_Init(
                ctx,
                key.as_ptr().cast(),
                key.len(),
                cipher.as_ptr(),
                ptr::null_mut(),
            ))?;
            cvt(ffi::CMAC_Update(ctx, data.as_ptr(), data.len()))?;
            let mut out = vec![0u8; 16];
            let mut out_len = 0usize;
            cvt(ffi::CMAC_Final(ctx, out.as_mut_ptr(), &mut out_len))?;
            out.truncate(out_len);
            Ok(out)
        })();
        ffi::CMAC_CTX_free(ctx);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    // NIST SP 800-38B CMAC-AES-128 예제(빈 메시지) 검증.
    #[test]
    fn cmac_aes128_empty() {
        let key = Vec::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let mac = cmac(Cipher::aes_128_cbc(), &key, &[]).unwrap();
        assert_eq!(hex::encode(mac), "bb1d6929e95937287fa37d129b756746");
    }
}
