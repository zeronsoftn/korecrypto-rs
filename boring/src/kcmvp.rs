//! KCMVP (validated cryptographic module) support.
//!
//! 검증된 암호모듈(KCMVP) 모드로 동작 중인지 확인한다. 내부적으로는
//! BoringSSL 의 FIPS 자가시험 프레임워크를 사용한다.
use crate::ffi;
use openssl_macros::corresponds;

/// Determines if the library is running in the KCMVP (validated) mode of
/// operation.
#[corresponds(KCMVP_mode)]
#[must_use]
pub fn enabled() -> bool {
    unsafe { ffi::KCMVP_mode() != 0 }
}

/// Returns the bit width of a single raw noise-source sample produced by
/// [`collect_raw_noise_samples`] — the `Len` field of a KCMVP entropy
/// assessment sample file. Returns 0 on platforms without a jitter noise
/// source.
#[corresponds(KCMVP_entropy_noise_sample_bits)]
#[must_use]
pub fn entropy_noise_sample_bits() -> u32 {
    unsafe { ffi::KCMVP_entropy_noise_sample_bits() as u32 }
}

/// Fills `out` with raw noise-source samples taken through the KCMVP module's
/// own jitter entropy path (for SP 800-90B entropy assessment). Each byte is
/// one sample. The whole buffer is collected in a single continuous run to
/// preserve the noise source's statistical characteristics.
///
/// Returns `true` on success, `false` on error (including platforms without a
/// jitter noise source).
#[corresponds(KCMVP_entropy_raw_noise_samples)]
#[must_use]
pub fn collect_raw_noise_samples(out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }
    unsafe { ffi::KCMVP_entropy_raw_noise_samples(out.as_mut_ptr(), out.len()) != 0 }
}

#[test]
fn is_enabled() {
    #[cfg(feature = "kcmvp")]
    assert!(enabled());
    #[cfg(not(feature = "kcmvp"))]
    assert!(!enabled());
}

#[cfg(feature = "kcmvp")]
#[test]
fn collects_raw_noise_samples() {
    assert_eq!(entropy_noise_sample_bits(), 8);
    let mut buf = [0u8; 1024];
    assert!(collect_raw_noise_samples(&mut buf));
    // 잡음원 출력이 상수로 고정되어 있지 않은지(모두 동일 값이 아닌지) 확인한다.
    assert!(buf.iter().any(|&b| b != buf[0]));
    // 빈 버퍼는 성공(수집할 것이 없음)으로 처리한다.
    assert!(collect_raw_noise_samples(&mut []));
}
