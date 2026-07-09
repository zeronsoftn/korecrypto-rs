// boringssl `util/fipstools/test_fips.cc` 의 Rust 포팅.
//
// test_fips.cc 는 FIPS 모듈이 FIPS 모드로 로드됐는지 확인하고, 승인 알고리즘
// (AES-KW/KWP/CBC/CCM/GCM, SHA-1/256/512, RSA, EC/ECDH-Z/ECDSA, CTR-DRBG, HKDF,
//  TLS-PRF, FFDH, ML-KEM, ML-DSA, SLH-DSA)을 실제로 한 번씩 수행하는 검증용 데모다.
// 이 테스트 바이너리는 FIPS boringssl 을 링크하므로 로드 시 "가동 전 자가시험"
// (무결성 검사 + KAT)이 생성자에서 실행되고, 실패하면 startup 에서 abort 한다.
// 즉 이 테스트가 실행됐다는 것 자체가 무결성/KAT 자가시험 통과를 의미하며, 이어서
// 각 승인 알고리즘 연산이 성공하는지 확인한다.
//
// korecrypto_sys(FFI)를 그대로 호출해 test_fips.cc 의 run_test() 를 전사한다.
// (TLS 1.3 KDF 만 예외: CRYPTO_tls13_hkdf_expand_label 는 공개 헤더에 없어 제외.
//  TLS 1.0/1.2 는 공개 CRYPTO_tls1_prf 로 수행한다.)
#![cfg(feature = "kcmvp")]

use korecrypto_sys as ffi;
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::ptr;

/// C 배열 초기화(`static const uint8_t k[N] = "..."`)를 그대로 흉내낸다:
/// N 바이트 0 채운 뒤 문자열 바이트를 앞부터 복사(널 종단 포함).
fn fixed<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut buf = [0u8; N];
    buf[..s.len()].copy_from_slice(s);
    buf
}

#[test]
fn test_fips_run_test() {
    unsafe { run_test() }
}

unsafe fn run_test() {
    // 0) FIPS 모드 + 모듈 정보. (여기 도달했다는 것은 로드 시 무결성/KAT 자가시험을
    //    이미 통과했다는 뜻이다.)
    assert_eq!(ffi::KCMVP_mode(), 1, "module not in KCMVP mode");
    // FIPS_version 은 released(검증된) 모듈에만 주입된다. 소스 빌드/CI 에서는 0 일 수
    // 있으므로(모듈은 여전히 FIPS 모드) 실패시키지 않고 로그만 남긴다.
    let version = ffi::KCMVP_version();
    let name = ffi::KCMVP_module_name();
    assert!(!name.is_null(), "FIPS_module_name returned null");
    let hash = ffi::KCMVP_module_hash();
    assert!(!hash.is_null(), "FIPS_module_hash returned null");
    eprintln!(
        "Module: {:?}, version: {}",
        std::ffi::CStr::from_ptr(name),
        version
    );

    let aes_key_bytes = fixed::<16>(b"BoringCrypto Ky");
    let plaintext = fixed::<64>(b"BoringCryptoModule FIPS KAT Encryption and Decryption Plaintext");
    let plaintext_sha256: [u8; 32] = [
        0x37, 0xbd, 0x70, 0x53, 0x72, 0xfc, 0xd4, 0x03, 0x79, 0x70, 0xfb, 0x06, 0x95, 0xb1, 0x2a,
        0x82, 0x48, 0xe1, 0x3e, 0xf2, 0x33, 0xfb, 0xef, 0x29, 0x81, 0x22, 0x45, 0x40, 0x43, 0x70,
        0xce, 0x0f,
    ];
    let mut output = [0u8; 256];

    // 1) AES 키 스케줄
    let mut aes_key = MaybeUninit::<ffi::AES_KEY>::uninit();
    assert_eq!(
        ffi::AES_set_encrypt_key(aes_key_bytes.as_ptr(), 128, aes_key.as_mut_ptr()),
        0,
        "AES_set_encrypt_key failed"
    );
    let mut aes_key = aes_key.assume_init();

    // AES-KW
    let kw_len = ffi::AES_wrap_key(
        &aes_key,
        ptr::null(),
        output.as_mut_ptr(),
        plaintext.as_ptr(),
        16,
    );
    assert_ne!(kw_len, -1, "AES_wrap_key failed");

    // AES-KWP
    let mut out_len: usize = 0;
    assert_eq!(
        ffi::AES_wrap_key_padded(
            &aes_key,
            output.as_mut_ptr(),
            &mut out_len,
            output.len(),
            plaintext.as_ptr(),
            16
        ),
        1,
        "AES_wrap_key_padded failed"
    );

    // AES-CBC encrypt
    let mut aes_iv = [0u8; 16];
    ffi::AES_cbc_encrypt(
        plaintext.as_ptr(),
        output.as_mut_ptr(),
        plaintext.len(),
        &aes_key,
        aes_iv.as_mut_ptr(),
        ffi::AES_ENCRYPT as c_int,
    );

    // AES-CBC decrypt
    aes_iv = [0u8; 16];
    assert_eq!(
        ffi::AES_set_decrypt_key(aes_key_bytes.as_ptr(), 128, &mut aes_key),
        0,
        "AES_set_decrypt_key failed"
    );
    ffi::AES_cbc_encrypt(
        output.as_ptr(),
        output.as_mut_ptr(),
        plaintext.len(),
        &aes_key,
        aes_iv.as_mut_ptr(),
        ffi::AES_DECRYPT as c_int,
    );

    // 2) AEAD: AES-CCM, AES-GCM (seal→open 왕복)
    let nonce = [0u8; 24]; // EVP_AEAD_MAX_NONCE_LENGTH 이상
    aead_roundtrip(
        ffi::EVP_aead_aes_128_ccm_bluetooth(),
        &aes_key_bytes,
        &nonce,
        &plaintext,
    );
    aead_roundtrip(
        ffi::EVP_aead_aes_128_gcm(),
        &aes_key_bytes,
        &nonce,
        &plaintext,
    );

    // 3) SHA-1/256/512
    assert!(!ffi::SHA1(plaintext.as_ptr(), plaintext.len(), output.as_mut_ptr()).is_null());
    assert!(!ffi::SHA256(plaintext.as_ptr(), plaintext.len(), output.as_mut_ptr()).is_null());
    assert!(!ffi::SHA512(plaintext.as_ptr(), plaintext.len(), output.as_mut_ptr()).is_null());

    // 4) RSA 키생성 + 서명/검증
    let rsa = ffi::RSA_new();
    assert!(!rsa.is_null());
    assert_eq!(
        ffi::RSA_generate_key_fips(rsa, 2048, ptr::null_mut()),
        1,
        "RSA_generate_key_fips failed"
    );
    let mut sig_len: u32 = 0;
    assert_eq!(
        ffi::RSA_sign(
            ffi::NID_sha256 as c_int,
            plaintext_sha256.as_ptr(),
            plaintext_sha256.len(),
            output.as_mut_ptr(),
            &mut sig_len,
            rsa
        ),
        1,
        "RSA_sign failed"
    );
    assert_eq!(
        ffi::RSA_verify(
            ffi::NID_sha256 as c_int,
            plaintext_sha256.as_ptr(),
            plaintext_sha256.len(),
            output.as_ptr(),
            sig_len as usize,
            rsa
        ),
        1,
        "RSA_verify failed"
    );
    ffi::RSA_free(rsa);

    // null 출력으로 RSA 키생성 → 실패해야 정상
    assert_eq!(
        ffi::RSA_generate_key_fips(ptr::null_mut(), 2048, ptr::null_mut()),
        0,
        "RSA_generate_key_fips unexpectedly succeeded with null output"
    );
    ffi::ERR_clear_error();

    // 5) EC: 키생성, 기본 Z 계산, ECDSA 서명/검증
    let ec_key = ffi::EC_KEY_new_by_curve_name(ffi::NID_X9_62_prime256v1 as c_int);
    assert!(!ec_key.is_null(), "invalid ECDSA key");
    assert_eq!(
        ffi::EC_KEY_generate_key_fips(ec_key),
        1,
        "EC_KEY_generate_key_fips failed"
    );

    let ec_group = ffi::EC_KEY_get0_group(ec_key);
    let z_point = ffi::EC_POINT_new(ec_group);
    let mut z_result = [0u8; 65];
    assert_eq!(
        ffi::EC_POINT_mul(
            ec_group,
            z_point,
            ptr::null(),
            ffi::EC_KEY_get0_public_key(ec_key),
            ffi::EC_KEY_get0_private_key(ec_key),
            ptr::null_mut()
        ),
        1,
        "EC_POINT_mul failed"
    );
    assert_eq!(
        ffi::EC_POINT_point2oct(
            ec_group,
            z_point,
            ffi::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
            z_result.as_mut_ptr(),
            z_result.len(),
            ptr::null_mut()
        ),
        z_result.len(),
        "EC_POINT_point2oct failed"
    );
    ffi::EC_POINT_free(z_point);

    // ECDSA 서명/검증 PWCT
    let sig = ffi::ECDSA_do_sign(plaintext_sha256.as_ptr(), plaintext_sha256.len(), ec_key);
    assert!(!sig.is_null(), "ECDSA_do_sign failed");
    assert_eq!(
        ffi::ECDSA_do_verify(
            plaintext_sha256.as_ptr(),
            plaintext_sha256.len(),
            sig,
            ec_key
        ),
        1,
        "ECDSA_do_verify failed"
    );
    ffi::ECDSA_SIG_free(sig);
    ffi::EC_KEY_free(ec_key);

    // null 출력으로 EC 키생성 → 실패해야 정상
    assert_eq!(
        ffi::EC_KEY_generate_key_fips(ptr::null_mut()),
        0,
        "EC_KEY_generate_key_fips unexpectedly succeeded with null output"
    );
    ffi::ERR_clear_error();

    // 잘못된 공개키 파싱 → 실패해야 정상
    let ec_key = ffi::EC_KEY_new_by_curve_name(ffi::NID_X9_62_prime256v1 as c_int);
    let not_valid = [1u8, 2, 3, 4, 5, 6];
    assert_eq!(
        ffi::EC_KEY_oct2key(ec_key, not_valid.as_ptr(), not_valid.len(), ptr::null_mut()),
        0,
        "parsing invalid ECDSA public key unexpectedly succeeded"
    );
    ffi::ERR_clear_error();
    ffi::EC_KEY_free(ec_key);

    // 6) CTR-DRBG (df 사용): seed → generate → reseed → generate
    let drbg_entropy = fixed::<48>(b"DBRG Initial Entropy");
    let drbg_nonce = fixed::<16>(b"DBRG Nonce");
    let drbg_personalization = fixed::<19>(b"BCMPersonalization");
    let drbg_ad = fixed::<16>(b"BCM DRBG AD");
    let drbg_entropy2 = fixed::<48>(b"DBRG Reseed Entropy");
    let drbg = ffi::CTR_DRBG_new_df(
        drbg_entropy.as_ptr(),
        drbg_entropy.len(),
        drbg_nonce.as_ptr(),
        drbg_personalization.as_ptr(),
        drbg_personalization.len(),
    );
    assert!(!drbg.is_null(), "CTR_DRBG_new_df failed");
    assert_eq!(
        ffi::CTR_DRBG_generate(
            drbg,
            output.as_mut_ptr(),
            output.len(),
            drbg_ad.as_ptr(),
            drbg_ad.len()
        ),
        1,
        "CTR_DRBG_generate failed"
    );
    assert_eq!(
        ffi::CTR_DRBG_reseed_ex(
            drbg,
            drbg_entropy2.as_ptr(),
            drbg_entropy2.len(),
            drbg_ad.as_ptr(),
            drbg_ad.len()
        ),
        1,
        "CTR_DRBG_reseed_ex failed"
    );
    assert_eq!(
        ffi::CTR_DRBG_generate(
            drbg,
            output.as_mut_ptr(),
            output.len(),
            drbg_ad.as_ptr(),
            drbg_ad.len()
        ),
        1,
        "CTR_DRBG_generate (post-reseed) failed"
    );
    ffi::CTR_DRBG_free(drbg);

    // 7) HKDF
    let salt = b"salt";
    let mut hkdf_output = [0u8; 32];
    assert_eq!(
        ffi::HKDF(
            hkdf_output.as_mut_ptr(),
            hkdf_output.len(),
            ffi::EVP_sha256(),
            aes_key_bytes.as_ptr(),
            aes_key_bytes.len(),
            salt.as_ptr(),
            salt.len(),
            plaintext_sha256.as_ptr(),
            plaintext_sha256.len(),
        ),
        1,
        "HKDF failed"
    );

    // 8) TLS PRF v1.0(md5_sha1) / v1.2(sha256)
    let label = b"foo";
    for digest in [ffi::EVP_md5_sha1(), ffi::EVP_sha256()] {
        let mut tls_output = [0u8; 32];
        assert_eq!(
            ffi::CRYPTO_tls1_prf(
                digest,
                tls_output.as_mut_ptr(),
                tls_output.len(),
                aes_key_bytes.as_ptr(),
                aes_key_bytes.len(),
                label.as_ptr(),
                label.len(),
                plaintext_sha256.as_ptr(),
                plaintext_sha256.len(),
                plaintext_sha256.as_ptr(),
                plaintext_sha256.len(),
            ),
            1,
            "CRYPTO_tls1_prf failed"
        );
    }

    // 9) FFDH (RFC 7919 ffdhe2048)
    let dh = ffi::DH_get_rfc7919_2048();
    assert!(!dh.is_null(), "DH_get_rfc7919_2048 failed");
    assert_eq!(ffi::DH_generate_key(dh), 1, "DH_generate_key failed");
    let dh_size = ffi::DH_size(dh) as usize;
    assert_eq!(dh_size, 2048 / 8, "unexpected DH size");
    let mut dh_result = vec![0u8; dh_size];
    assert_eq!(
        ffi::DH_compute_key_padded(dh_result.as_mut_ptr(), ffi::DH_get0_pub_key(dh), dh) as usize,
        dh_size,
        "DH_compute_key_padded failed"
    );
    ffi::DH_free(dh);

    // 10) ML-KEM (FIPS 203): keygen → encap → decap
    let mut mlkem_pub_bytes = vec![0u8; ffi::MLKEM768_PUBLIC_KEY_BYTES as usize];
    let mut mlkem_priv = MaybeUninit::<ffi::MLKEM768_private_key>::uninit();
    ffi::MLKEM768_generate_key(
        mlkem_pub_bytes.as_mut_ptr(),
        ptr::null_mut(),
        mlkem_priv.as_mut_ptr(),
    );
    let mlkem_priv = mlkem_priv.assume_init();
    let mut mlkem_pub = MaybeUninit::<ffi::MLKEM768_public_key>::uninit();
    ffi::MLKEM768_public_from_private(mlkem_pub.as_mut_ptr(), &mlkem_priv);
    let mlkem_pub = mlkem_pub.assume_init();
    let mut mlkem_ct = vec![0u8; ffi::MLKEM768_CIPHERTEXT_BYTES as usize];
    let mut mlkem_ss = [0u8; ffi::MLKEM_SHARED_SECRET_BYTES as usize];
    ffi::MLKEM768_encap(mlkem_ct.as_mut_ptr(), mlkem_ss.as_mut_ptr(), &mlkem_pub);
    let mut mlkem_ss2 = [0u8; ffi::MLKEM_SHARED_SECRET_BYTES as usize];
    assert_eq!(
        ffi::MLKEM768_decap(
            mlkem_ss2.as_mut_ptr(),
            mlkem_ct.as_ptr(),
            mlkem_ct.len(),
            &mlkem_priv
        ),
        1,
        "MLKEM768_decap failed"
    );
    assert_eq!(mlkem_ss, mlkem_ss2, "ML-KEM shared secret mismatch");

    // 11) ML-DSA (FIPS 204): keygen → sign → verify
    let mut mldsa_pub_bytes = vec![0u8; ffi::MLDSA65_PUBLIC_KEY_BYTES as usize];
    let mut mldsa_seed = [0u8; ffi::MLDSA_SEED_BYTES as usize];
    let mut mldsa_priv = MaybeUninit::<ffi::MLDSA65_private_key>::uninit();
    assert_eq!(
        ffi::MLDSA65_generate_key(
            mldsa_pub_bytes.as_mut_ptr(),
            mldsa_seed.as_mut_ptr(),
            mldsa_priv.as_mut_ptr()
        ),
        1,
        "MLDSA65_generate_key failed"
    );
    let mldsa_priv = mldsa_priv.assume_init();
    let mut mldsa_sig = vec![0u8; ffi::MLDSA65_SIGNATURE_BYTES as usize];
    assert_eq!(
        ffi::MLDSA65_sign(
            mldsa_sig.as_mut_ptr(),
            &mldsa_priv,
            ptr::null(),
            0,
            ptr::null(),
            0
        ),
        1,
        "MLDSA65_sign failed"
    );
    let mut mldsa_pub = MaybeUninit::<ffi::MLDSA65_public_key>::uninit();
    assert_eq!(
        ffi::MLDSA65_public_from_private(mldsa_pub.as_mut_ptr(), &mldsa_priv),
        1,
        "MLDSA65_public_from_private failed"
    );
    let mldsa_pub = mldsa_pub.assume_init();
    assert_eq!(
        ffi::MLDSA65_verify(
            &mldsa_pub,
            mldsa_sig.as_ptr(),
            mldsa_sig.len(),
            ptr::null(),
            0,
            ptr::null(),
            0
        ),
        1,
        "MLDSA65_verify failed"
    );

    // 12) SLH-DSA (FIPS 205): keygen → sign → verify
    let mut slhdsa_pub = [0u8; ffi::SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES as usize];
    let mut slhdsa_priv = [0u8; ffi::SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES as usize];
    ffi::SLHDSA_SHA2_128S_generate_key(slhdsa_pub.as_mut_ptr(), slhdsa_priv.as_mut_ptr());
    let mut slhdsa_sig = vec![0u8; ffi::SLHDSA_SHA2_128S_SIGNATURE_BYTES as usize];
    assert_eq!(
        ffi::SLHDSA_SHA2_128S_sign(
            slhdsa_sig.as_mut_ptr(),
            slhdsa_priv.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            0
        ),
        1,
        "SLHDSA_SHA2_128S_sign failed"
    );
    assert_eq!(
        ffi::SLHDSA_SHA2_128S_verify(
            slhdsa_sig.as_ptr(),
            slhdsa_sig.len(),
            slhdsa_pub.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            0
        ),
        1,
        "SLHDSA_SHA2_128S_verify failed"
    );

    eprintln!("PASS");
}

/// AEAD seal → open 왕복. seal 결과를 다시 open 해 원문이 복원되는지 확인한다.
unsafe fn aead_roundtrip(aead: *const ffi::EVP_AEAD, key: &[u8], nonce: &[u8], plaintext: &[u8]) {
    let ctx = ffi::EVP_AEAD_CTX_new(aead, key.as_ptr(), key.len(), 0);
    assert!(!ctx.is_null(), "EVP_AEAD_CTX_new failed");
    let nonce_len = ffi::EVP_AEAD_nonce_length(aead);
    let mut sealed = vec![0u8; plaintext.len() + ffi::EVP_AEAD_max_overhead(aead)];
    let mut sealed_len: usize = 0;
    assert_eq!(
        ffi::EVP_AEAD_CTX_seal(
            ctx,
            sealed.as_mut_ptr(),
            &mut sealed_len,
            sealed.len(),
            nonce.as_ptr(),
            nonce_len,
            plaintext.as_ptr(),
            plaintext.len(),
            ptr::null(),
            0,
        ),
        1,
        "EVP_AEAD_CTX_seal failed"
    );
    let mut opened = vec![0u8; sealed_len];
    let mut opened_len: usize = 0;
    assert_eq!(
        ffi::EVP_AEAD_CTX_open(
            ctx,
            opened.as_mut_ptr(),
            &mut opened_len,
            opened.len(),
            nonce.as_ptr(),
            nonce_len,
            sealed.as_ptr(),
            sealed_len,
            ptr::null(),
            0,
        ),
        1,
        "EVP_AEAD_CTX_open failed"
    );
    assert_eq!(&opened[..opened_len], plaintext, "AEAD roundtrip mismatch");
    ffi::EVP_AEAD_CTX_free(ctx);
}
