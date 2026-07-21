//! Bindings to BoringSSL
//!
//! This crate provides a safe interface to the BoringSSL cryptography library.
//!
//! # Versioning
//!
//! ## Crate versioning
//!
//! The crate and all the related crates (FFI bindings, etc.) are released simultaneously and all
//! bumped to the same version disregard whether particular crate has any API changes or not.
//! However, semantic versioning guarantees still hold, as all the crate versions will be updated
//! based on the crate with most significant changes.
//!
//! ## BoringSSL version
//!
//! By default, the crate aims to statically link with the latest BoringSSL master branch.
//! *Note*: any BoringSSL revision bumps will be released as a major version update of all crates.
//!
//! # Compilation and linking options
//!
//! ## Environment variables
//!
//! This crate uses various environment variables to tweak how boring is built. The variables
//! are all prefixed by `BORING_BSSL_` for non-KCMVP builds, and by `KORECRYPTO_FIPS_` for KCMVP builds.
//! Below, `BORING_BSSL{→KORECRYPTO_FIPS}_X` denotes `BORING_BSSL_X` normally, or `KORECRYPTO_FIPS_X`
//! when the `kcmvp` feature is enabled.
//!
//! ## Support for pre-built binaries or custom source
//!
//! While this crate can build BoringSSL on its own, you may want to provide pre-built binaries instead.
//! To do so, specify the environment variable `BORING_BSSL{→KORECRYPTO_FIPS}_PATH` with the path to the binaries.
//!
//! You can also provide specific headers by setting `BORING_BSSL{→KORECRYPTO_FIPS}_INCLUDE_PATH`.
//!
//! _Notes_: The crate will look for headers in the`$BORING_BSSL{→KORECRYPTO_FIPS}_INCLUDE_PATH/openssl/`
//! folder, make sure to place your headers there.
//!
//! In alternative a different path for the BoringSSL source code directory can be specified by setting
//! `BORING_BSSL{→KORECRYPTO_FIPS}_SOURCE_PATH` which will automatically be compiled during the build process.
//!
//! _Warning_: When providing a different version of BoringSSL make sure to use a compatible one, the
//! crate relies on the presence of certain functions.
//!
//! ## Building with a FIPS-validated module
//!
//! Only BoringCrypto module version `853ca1ea1168dff08011e5d42d94609cc0ca2e27`, as certified with
//! [FIPS 140-2 certificate 4407](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4407)
//! is supported by this crate. Support is enabled by this crate's `kcmvp` feature.
//!
//! `boring-sys` comes with a test that FIPS is enabled/disabled depending on the feature flag. You can run it as follows:
//!
//! ```bash
//! $ cargo test --features kcmvp kcmvp::is_enabled
//! ```
//!
//! ## Linking current BoringSSL version with precompiled FIPS-validated module (`bcm.o`)
//!
//! It's possible to link latest supported version of BoringSSL with FIPS-validated crypto module
//! (`bcm.o`). To enable this compilation option one should enable `fips-link-precompiled`
//! compilation feature and provide a `KORECRYPTO_FIPS_PRECOMPILED_BCM_O` env variable with a path to the
//! precompiled FIPS-validated `bcm.o` module.
//!
//! Note that `BORING_BSSL_PRECOMPILED_BCM_O` is never used, as linking BoringSSL with precompiled non-FIPS
//! module is not supported.
//!
//! ## Linking with a C++ standard library
//!
//! Recent versions of boringssl require some C++ standard library features, so boring needs to link
//! with a STL implementation. This can be controlled using the BORING_BSSL_RUST_CPPLIB variable. If
//! no library is specified, libc++ is used on macOS and iOS whereas libstdc++ is used on other Unix
//! systems.
//!
//! # Optional patches
//!
//! ## Raw Public Key
//!
//! The crate can be compiled with [RawPublicKey](https://datatracker.ietf.org/doc/html/rfc7250)
//! support by turning on `rpk` compilation feature.
//!
//! ## Experimental post-quantum cryptography
//!
//! The crate can be compiled with [post-quantum cryptography](https://blog.cloudflare.com/post-quantum-for-all/)
//! support by turning on `post-quantum` compilation feature.
//!
//! Upstream BoringSSL support the post-quantum hybrid key agreement `X25519Kyber768Draft00`. Most
//! users should stick to that one for now. Enabling this feature, adds a few other post-quantum key
//! agreements:
//!
//! - `X25519MLKEM768` is the successor of `X25519Kyber768Draft00`. We expect servers to switch
//!   before the end of 2024.
//! - `X25519Kyber768Draft00Old` is the same as `X25519Kyber768Draft00`, but under its old codepoint.
//! - `X25519Kyber512Draft00`. Similar to `X25519Kyber768Draft00`, but uses level 1 parameter set for
//!   Kyber. Not recommended. It's useful to test whether the shorter ClientHello upsets fewer middle
//!   boxes.
//! - `P256Kyber768Draft00`. Similar again to `X25519Kyber768Draft00`, but uses P256 as classical
//!   part. It uses a non-standard codepoint. Not recommended.
//!
//! Presently all these key agreements are deployed by Cloudflare, but we do not guarantee continued
//! support for them.

// baremetal(UEFI 등 freestanding no_std) 빌드에서는 crate 전체를 no_std 로 만든다.
// std 를 링크하면 std 가 정의하는 lang item(panic_impl 등)이 no_std 실행 파일이
// 제공하는 것과 충돌한다(E0152). 이 경우 저수준 `sys` FFI 와 no_std 안전 모듈만
// 노출하고, std 에 의존하는 고수준 API 는 전부 제외한다.
#![cfg_attr(feature = "baremetal", no_std)]

#[cfg(all(feature = "std-libc", not(feature = "picolibc")))]
extern crate libc;

#[cfg(feature = "picolibc")]
extern crate picolibc as libc;

#[cfg(not(feature = "baremetal"))]
#[macro_use]
extern crate bitflags;
#[cfg(not(feature = "baremetal"))]
#[macro_use]
extern crate foreign_types;
extern crate korecrypto_sys as ffi;

#[cfg(test)]
extern crate hex;

#[doc(inline)]
pub use crate::ffi::init;

/// Re-export of the low-level `korecrypto-sys` FFI bindings, so downstream
/// crates can depend on `korecrypto` alone and still reach the raw C API
/// (e.g. `korecrypto::sys::CRYPTO_uefi_init`).
pub use ::korecrypto_sys as sys;

// KCMVP 상태/엔트로피 API 는 no_std 안전(ffi 만 사용)하므로 baremetal 에서도 노출한다.
pub mod kcmvp;

// ---- 이하 고수준 API 는 std 에 의존하므로 baremetal(no_std)에서는 제외한다 ----
#[cfg(not(feature = "baremetal"))]
mod std_api {
    pub(crate) use std::ffi::{c_int, c_long, c_void};
    pub(crate) use std::num::NonZeroUsize;
}
#[cfg(not(feature = "baremetal"))]
use std_api::{c_int, c_long, c_void, NonZeroUsize};

#[cfg(not(feature = "baremetal"))]
use crate::error::ErrorStack;

#[cfg(not(feature = "baremetal"))]
#[macro_use]
mod macros;

#[cfg(not(feature = "baremetal"))]
mod bio;
#[cfg(not(feature = "baremetal"))]
#[macro_use]
mod util;

#[cfg(not(feature = "baremetal"))]
pub mod aead;
#[cfg(not(feature = "baremetal"))]
pub mod aes;
#[cfg(not(feature = "baremetal"))]
pub mod asn1;
#[cfg(not(feature = "baremetal"))]
pub mod base64;
#[cfg(not(feature = "baremetal"))]
pub mod bn;
#[cfg(not(feature = "baremetal"))]
pub mod cmac;
#[cfg(not(feature = "baremetal"))]
pub mod conf;
#[cfg(not(feature = "baremetal"))]
pub mod derive;
#[cfg(not(feature = "baremetal"))]
pub mod dh;
#[cfg(not(feature = "baremetal"))]
pub mod drbg;
#[cfg(not(feature = "baremetal"))]
pub mod dsa;
#[cfg(not(feature = "baremetal"))]
pub mod ec;
#[cfg(not(feature = "baremetal"))]
pub mod ecdsa;
#[cfg(not(feature = "baremetal"))]
pub mod eckcdsa;
#[cfg(not(feature = "baremetal"))]
pub mod error;
#[cfg(not(feature = "baremetal"))]
pub mod ex_data;
#[cfg(not(feature = "baremetal"))]
pub mod hash;
#[cfg(not(feature = "baremetal"))]
pub mod hmac;
#[cfg(not(feature = "baremetal"))]
pub mod hpke;
#[cfg(not(feature = "baremetal"))]
pub mod kcdsa;
#[cfg(not(feature = "baremetal"))]
pub mod kdf;
#[cfg(not(feature = "baremetal"))]
pub mod memcmp;
#[cfg(all(not(feature = "baremetal"), feature = "mlkem"))]
pub mod mlkem;
#[cfg(not(feature = "baremetal"))]
pub mod nid;
#[cfg(not(feature = "baremetal"))]
pub mod pkcs12;
#[cfg(not(feature = "baremetal"))]
pub mod pkcs5;
#[cfg(not(feature = "baremetal"))]
pub mod pkey;
#[cfg(all(not(feature = "baremetal"), feature = "prf"))]
pub mod prf;
#[cfg(not(feature = "baremetal"))]
pub mod rand;
#[cfg(not(feature = "baremetal"))]
pub mod rsa;
#[cfg(not(feature = "baremetal"))]
pub mod sha;
#[cfg(not(feature = "baremetal"))]
pub mod sign;
#[cfg(not(feature = "baremetal"))]
pub mod srtp;
#[cfg(not(feature = "baremetal"))]
pub mod ssl;
#[cfg(not(feature = "baremetal"))]
pub mod stack;
#[cfg(not(feature = "baremetal"))]
pub mod string;
#[cfg(not(feature = "baremetal"))]
pub mod symm;
#[cfg(not(feature = "baremetal"))]
pub mod version;
#[cfg(not(feature = "baremetal"))]
pub mod x509;

#[cfg(not(feature = "baremetal"))]
fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[cfg(not(feature = "baremetal"))]
fn cvt_0(r: usize) -> Result<(), ErrorStack> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(())
    }
}

#[cfg(not(feature = "baremetal"))]
fn cvt_0i(r: c_int) -> Result<c_int, ErrorStack> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[cfg(not(feature = "baremetal"))]
fn cvt(r: c_int) -> Result<(), ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(())
    }
}

#[cfg(not(feature = "baremetal"))]
fn cvt_nz(r: c_int) -> Result<NonZeroUsize, ErrorStack> {
    usize::try_from(r)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(ErrorStack::get)
}

#[cfg(not(feature = "baremetal"))]
fn cvt_n(r: c_int) -> Result<c_int, ErrorStack> {
    if r < 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[cfg(not(feature = "baremetal"))]
fn try_int<F, T>(from: F) -> Result<T, ErrorStack>
where
    F: TryInto<T> + Send + Sync + Copy + 'static,
    T: Send + Sync + Copy + 'static,
{
    from.try_into()
        .map_err(|_| ErrorStack::internal_error_str("int overflow"))
}

#[cfg(not(feature = "baremetal"))]
unsafe extern "C" fn free_data_box<T>(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::<T>::from_raw(ptr.cast::<T>()));
        }
    }
}
