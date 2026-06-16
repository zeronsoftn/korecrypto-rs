//! KCDSA (한국형 전자서명, TTAK.KO-12.0001).
//!
//! KCMVP 검증대상 전자서명. 이산대수 기반으로 도메인 파라미터 (P, Q, G) 와 키
//! 쌍 (x, y) 를 가진다. 공개키는 y = G^{x^{-1} mod Q} mod P 로 정의된다.
//! 해시는 SHA-224(|Q|=224) 또는 SHA-256(|Q|=256) 을 사용한다.

use crate::error::ErrorStack;
use crate::ffi;
use crate::hash::MessageDigest;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::KCDSA_KEY;
    fn drop = ffi::KCDSA_KEY_free;

    /// KCDSA 키(도메인 파라미터 + 키 쌍).
    pub struct KcdsaKey;
}

impl KcdsaKey {
    /// 빈 키를 생성한다.
    pub fn new() -> Result<Self, ErrorStack> {
        crate::ffi::init();
        unsafe {
            let ptr = ffi::KCDSA_KEY_new();
            if ptr.is_null() {
                Err(ErrorStack::get())
            } else {
                Ok(KcdsaKey::from_ptr(ptr))
            }
        }
    }

    /// 도메인 파라미터 P, Q, G(각 빅엔디안)를 설정한다.
    pub fn set_params(&mut self, p: &[u8], q: &[u8], g: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::KCDSA_KEY_set_params(
                self.as_ptr(),
                p.as_ptr(),
                p.len(),
                q.as_ptr(),
                q.len(),
                g.as_ptr(),
                g.len(),
            ) == 1
            {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// 개인키 x(빅엔디안)를 설정하고 공개키 y 를 계산한다.
    pub fn set_private(&mut self, x: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::KCDSA_KEY_set_private(self.as_ptr(), x.as_ptr(), x.len()) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// 개인키를 무작위 생성하고 공개키 계산 후 키쌍 일치시험(PCT)을 수행한다.
    /// 도메인 파라미터가 먼저 설정되어야 한다.
    pub fn generate(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::KCDSA_KEY_generate(self.as_ptr()) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// 검증용으로 공개키 y(빅엔디안)를 직접 설정한다.
    pub fn set_public(&mut self, y: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            if ffi::KCDSA_KEY_set_public(self.as_ptr(), y.as_ptr(), y.len()) == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }
}

impl KcdsaKeyRef {
    /// 서명 길이(2*|Q|바이트).
    pub fn sig_len(&self) -> usize {
        unsafe { ffi::KCDSA_sig_len(self.as_ptr()) }
    }

    /// `msg` 에 서명한다. `k` 가 `Some` 이면 그 난수(빅엔디안)를 사용하고,
    /// `None` 이면 내부 난수를 생성한다.
    pub fn sign(
        &self,
        md: MessageDigest,
        msg: &[u8],
        k: Option<&[u8]>,
    ) -> Result<Vec<u8>, ErrorStack> {
        let mut sig = vec![0u8; self.sig_len()];
        let mut sig_len = 0usize;
        let (kp, kl) = match k {
            Some(k) => (k.as_ptr(), k.len()),
            None => (ptr::null(), 0),
        };
        unsafe {
            if ffi::KCDSA_sign(
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
            ffi::KCDSA_verify(
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
    use hex::FromHex;

    // KISA KCDSA 참조구현(P=2048, Q=224, SHA-224) 교차검증 KAT.
    #[test]
    fn kcdsa_2048_224_sha224_kat() {
        let p = Vec::from_hex(
            "e3ebf32e0defa392abc145feb22a40cf5e2d360d51a41d0e7b60d231cde3f8ddd8a45f7e32339d5506845f125ed1283c224f322ed3bffa1a5553f7e00a977cdc2358a007096130094380f0d228020e8be65790a97265174e9ae9f34b4b80c9f6972abbb7a3af6d290508ecabf8205d90ea386238893313c429f9c6af64409885b368ebd99525234f71a9e6e33beff92adbb8e8bd85dc8b3614ab64820422d4182e1fe6bf250a63c05f15533a451928dc020cb81ee014f01958d3188fc031602be1c2ea99a0896c95bde0947ac0849383d7f7a97cbcc6b58e8fd04c25d0f1c6a377005e4c7c5c51ec3bed34ba77d329846b0edb6924e1b3af22a7ec7a13db77c7",
        )
        .unwrap();
        let q = Vec::from_hex("da519c444dc8c2ba4c9f969be995da7c1876ef556264b71e118782d3").unwrap();
        let g = Vec::from_hex(
            "5b3d2e709ba64470d1faa0fedc5cacfbede9e2e324840e1935605be24030d45758f124f09739e920a6746e04d1d514628fe436a755462a2471e20d1cc1e92307f06ed247a66a82ced22d0ab2ccd9de1ecdf5ca7a573e18883bbfb23f94e41c654c15caa5593da54ea0eb37a97c47e11584bd9976955ed601700cf0ef566ec50be4e37e9bf9c043d2edfe0504cbfad9ca5e40c67affa86a84a61512d820d272fa4caacfa6539cab9fefb26414875f27386371c802b8acccb31c09b782a6bb558c21c6a531202222b14091f61e0c778cec433cc27476611c279648a690d2ab8a748d6b21e1b3059cc378dcc3a5d381a76ea2653367ea75cab581d84920e2bac9df",
        )
        .unwrap();
        let x = Vec::from_hex("02a4990163deb724ef9c985c2d721d4038d03d677d798b7c4de3bf81").unwrap();
        let k = Vec::from_hex("34b8cbcfe41821b18940f228e9c862b3c5fcf9773042c547f1f1ad9c").unwrap();
        let msg = Vec::from_hex(
            "5468697320697320612074657374206d65737361676520666f72204b4344534120757361676521",
        )
        .unwrap();
        let expected_r =
            Vec::from_hex("fb41e70475444d88ef4e2e29eaffc40343534d57062eab0905c5c8d0").unwrap();
        let expected_s =
            Vec::from_hex("229cdaf4f915cfbff2f2388beb898f630f86526f1006598bf085dc1d").unwrap();

        let mut key = KcdsaKey::new().unwrap();
        key.set_params(&p, &q, &g).unwrap();
        key.set_private(&x).unwrap();

        let sig = key.sign(MessageDigest::sha224(), &msg, Some(&k)).unwrap();
        let mut expected = expected_r.clone();
        expected.extend_from_slice(&expected_s);
        assert_eq!(sig, expected, "signature mismatch");

        assert!(key.verify(MessageDigest::sha224(), &msg, &sig));

        // 메시지 변조 시 검증 실패.
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert!(!key.verify(MessageDigest::sha224(), &bad, &sig));
    }

    // 내부 난수 사용 시 sign→verify 왕복.
    #[test]
    fn kcdsa_roundtrip_random_k() {
        let p = Vec::from_hex(
            "e3ebf32e0defa392abc145feb22a40cf5e2d360d51a41d0e7b60d231cde3f8ddd8a45f7e32339d5506845f125ed1283c224f322ed3bffa1a5553f7e00a977cdc2358a007096130094380f0d228020e8be65790a97265174e9ae9f34b4b80c9f6972abbb7a3af6d290508ecabf8205d90ea386238893313c429f9c6af64409885b368ebd99525234f71a9e6e33beff92adbb8e8bd85dc8b3614ab64820422d4182e1fe6bf250a63c05f15533a451928dc020cb81ee014f01958d3188fc031602be1c2ea99a0896c95bde0947ac0849383d7f7a97cbcc6b58e8fd04c25d0f1c6a377005e4c7c5c51ec3bed34ba77d329846b0edb6924e1b3af22a7ec7a13db77c7",
        )
        .unwrap();
        let q = Vec::from_hex("da519c444dc8c2ba4c9f969be995da7c1876ef556264b71e118782d3").unwrap();
        let g = Vec::from_hex(
            "5b3d2e709ba64470d1faa0fedc5cacfbede9e2e324840e1935605be24030d45758f124f09739e920a6746e04d1d514628fe436a755462a2471e20d1cc1e92307f06ed247a66a82ced22d0ab2ccd9de1ecdf5ca7a573e18883bbfb23f94e41c654c15caa5593da54ea0eb37a97c47e11584bd9976955ed601700cf0ef566ec50be4e37e9bf9c043d2edfe0504cbfad9ca5e40c67affa86a84a61512d820d272fa4caacfa6539cab9fefb26414875f27386371c802b8acccb31c09b782a6bb558c21c6a531202222b14091f61e0c778cec433cc27476611c279648a690d2ab8a748d6b21e1b3059cc378dcc3a5d381a76ea2653367ea75cab581d84920e2bac9df",
        )
        .unwrap();
        let x = Vec::from_hex("02a4990163deb724ef9c985c2d721d4038d03d677d798b7c4de3bf81").unwrap();

        let mut key = KcdsaKey::new().unwrap();
        key.set_params(&p, &q, &g).unwrap();
        key.set_private(&x).unwrap();
        let msg = b"hello kcdsa";
        let sig = key.sign(MessageDigest::sha224(), msg, None).unwrap();
        assert!(key.verify(MessageDigest::sha224(), msg, &sig));
    }

    // KISA KCDSA 참조구현(P=2048, Q=256, SHA-256) 교차검증 KAT.
    #[test]
    fn kcdsa_2048_256_sha256_kat() {
        let p = Vec::from_hex(
            "f54201c59ffd3fc4a78c2a4360bc00480440b9dcc3ce9e4403a202ac86049cb718bbbd2c6fd7ef12e4f372445352d691e2892006a9e8f70b1cfa4cc2b3b23034b8f55d582a899cdb4f1fd1c1ce3903535a4b4781c1cfbbd3a35649f1b7e3f76b729a3fe1e4b3096d18741c612449f674d5118c1fd214512c85cc111fb68a5e98e5dd854ec840b5f8b1b1da49ceccae6682573d520bdb2be3960567460699a82873b8a37c408ae228d5fc1fe71a221853c98d8b9a1eb4fbb2e027e5a557e1348c962dfa3e7e2a5d2355d94fc05a10f12b464c91893a66bb162d91e00054f2a2bd616a7824b73c3327edbbaca2cf822148a5e67568d4f87dd27afe7f13e2e669eb",
        )
        .unwrap();
        let q = Vec::from_hex("f09874cd7d130d1bd757e5ef11ad3a5de42b8efa20c01e7a877f85491d2708cd")
            .unwrap();
        let g = Vec::from_hex(
            "b971122ec28de061668c5bcc0dae9b9e7b01ba170f487ea0f5bb7025cb468bed051a9ee7eca8ff27ca143c72f4718780779351db263ed08cc9ed9e56b6a37812b576c5abbca1f2da2ee9a91b680725c62f4e212f6b48cdcbb8df5f92f22a1d2450ed6f66c00e3d14d00442c33f69c9796fa46bdafd96114a1a9647961ba42d172474755d5bbbbf86c6d61c35efcfd94c2dee54f56da7e8b7d79d42b7077eb23018ef0e914d1bd72832afc0a47181c4d9c71d15faa87480f6ed66c1fef4f26d50b6c5b3a3213a8efb7656a1fe7595fa392eec9507e177ae8d79b7c252d1978b588f7c5c1004a4a9bf57202be288a5592db0ff2af8ad1a90c7f3750452080dbc47",
        )
        .unwrap();
        let x = Vec::from_hex("7a132d9456f72626ca7159e213f494b1d678979bb35cebfaac6644960e1af03b")
            .unwrap();
        let k = Vec::from_hex("00dd689b3d2e936547e68220f01a445c98b7e7ec0a2e697b76a8f55fc05e3029")
            .unwrap();
        let msg = Vec::from_hex(
            "5468697320697320612074657374206d65737361676520666f72204b4344534120757361676521",
        )
        .unwrap();
        let expected_r =
            Vec::from_hex("57dc873315ba33bd7357813cbe9fde0d073d9ced31dd29d003d264d334cdca58")
                .unwrap();
        let expected_s =
            Vec::from_hex("6a11737edb5e504d73923d9a70c1f56d0309a9903ad03c9a6d467c6f4e53dfda")
                .unwrap();

        let mut key = KcdsaKey::new().unwrap();
        key.set_params(&p, &q, &g).unwrap();
        key.set_private(&x).unwrap();

        let sig = key.sign(MessageDigest::sha256(), &msg, Some(&k)).unwrap();
        let mut expected = expected_r.clone();
        expected.extend_from_slice(&expected_s);
        assert_eq!(sig, expected, "signature mismatch");
        assert!(key.verify(MessageDigest::sha256(), &msg, &sig));
    }

    // 키 생성 + PCT 후 sign→verify 왕복(참조 도메인 파라미터 재사용).
    #[test]
    fn kcdsa_generate_and_sign() {
        let p = Vec::from_hex(
            "e3ebf32e0defa392abc145feb22a40cf5e2d360d51a41d0e7b60d231cde3f8ddd8a45f7e32339d5506845f125ed1283c224f322ed3bffa1a5553f7e00a977cdc2358a007096130094380f0d228020e8be65790a97265174e9ae9f34b4b80c9f6972abbb7a3af6d290508ecabf8205d90ea386238893313c429f9c6af64409885b368ebd99525234f71a9e6e33beff92adbb8e8bd85dc8b3614ab64820422d4182e1fe6bf250a63c05f15533a451928dc020cb81ee014f01958d3188fc031602be1c2ea99a0896c95bde0947ac0849383d7f7a97cbcc6b58e8fd04c25d0f1c6a377005e4c7c5c51ec3bed34ba77d329846b0edb6924e1b3af22a7ec7a13db77c7",
        )
        .unwrap();
        let q = Vec::from_hex("da519c444dc8c2ba4c9f969be995da7c1876ef556264b71e118782d3").unwrap();
        let g = Vec::from_hex(
            "5b3d2e709ba64470d1faa0fedc5cacfbede9e2e324840e1935605be24030d45758f124f09739e920a6746e04d1d514628fe436a755462a2471e20d1cc1e92307f06ed247a66a82ced22d0ab2ccd9de1ecdf5ca7a573e18883bbfb23f94e41c654c15caa5593da54ea0eb37a97c47e11584bd9976955ed601700cf0ef566ec50be4e37e9bf9c043d2edfe0504cbfad9ca5e40c67affa86a84a61512d820d272fa4caacfa6539cab9fefb26414875f27386371c802b8acccb31c09b782a6bb558c21c6a531202222b14091f61e0c778cec433cc27476611c279648a690d2ab8a748d6b21e1b3059cc378dcc3a5d381a76ea2653367ea75cab581d84920e2bac9df",
        )
        .unwrap();

        let mut key = KcdsaKey::new().unwrap();
        key.set_params(&p, &q, &g).unwrap();
        key.generate().unwrap();
        let msg = b"generated kcdsa key";
        let sig = key.sign(MessageDigest::sha224(), msg, None).unwrap();
        assert!(key.verify(MessageDigest::sha224(), msg, &sig));
    }
}
