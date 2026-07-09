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

#[test]
fn is_enabled() {
    #[cfg(feature = "kcmvp")]
    assert!(enabled());
    #[cfg(not(feature = "kcmvp"))]
    assert!(!enabled());
}
