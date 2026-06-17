//! Key-based key derivation function (KBKDF, SP 800-108 / TTAK.KO-12.0272).
//!
//! These are KCMVP validation-target KDFs built on an HMAC PRF. The input
//! encoding matches the KISA reference (`[i]_r || Label || 0x00 || Context ||
//! [L]`, where `[L]` is the output length in bits as the minimum number of
//! big-endian bytes).

use crate::error::ErrorStack;
use crate::ffi;
use crate::hash::MessageDigest;

/// Derives `out.len()` bytes using SP 800-108 counter mode with an HMAC PRF.
///
/// `counter_bytes` is the width, in bytes, of the encoded loop counter
/// (typically 1 or 4).
pub fn kbkdf_hmac_counter(
    md: MessageDigest,
    ki: &[u8],
    counter_bytes: u32,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), ErrorStack> {
    crate::ffi::init();
    let ret = unsafe {
        ffi::KBKDF_hmac_counter(
            md.as_ptr(),
            ki.as_ptr(),
            ki.len(),
            counter_bytes,
            label.as_ptr(),
            label.len(),
            context.as_ptr(),
            context.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if ret == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
}

/// Derives `out.len()` bytes using SP 800-108 feedback mode (with counter) and
/// an HMAC PRF. `iv` is `K(0)`; pass an empty slice for an all-zero IV.
pub fn kbkdf_hmac_feedback(
    md: MessageDigest,
    ki: &[u8],
    counter_bytes: u32,
    label: &[u8],
    context: &[u8],
    iv: &[u8],
    out: &mut [u8],
) -> Result<(), ErrorStack> {
    crate::ffi::init();
    let ret = unsafe {
        ffi::KBKDF_hmac_feedback(
            md.as_ptr(),
            ki.as_ptr(),
            ki.len(),
            counter_bytes,
            label.as_ptr(),
            label.len(),
            context.as_ptr(),
            context.len(),
            iv.as_ptr(),
            iv.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if ret == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
}

/// Derives `out.len()` bytes using SP 800-108 double-pipeline mode and an HMAC
/// PRF. `counter_bytes` 0 omits the counter (the no-counter variant).
pub fn kbkdf_hmac_double_pipeline(
    md: MessageDigest,
    ki: &[u8],
    counter_bytes: u32,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), ErrorStack> {
    crate::ffi::init();
    let ret = unsafe {
        ffi::KBKDF_hmac_double_pipeline(
            md.as_ptr(),
            ki.as_ptr(),
            ki.len(),
            counter_bytes,
            label.as_ptr(),
            label.len(),
            context.as_ptr(),
            context.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if ret == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    // KBKDF-HMAC-SHA256-CTR KATs from the KISA reference (r=8 -> counter_bytes=1).
    #[test]
    fn kbkdf_hmac_counter_kat() {
        struct V {
            ki: &'static str,
            label: &'static str,
            context: &'static str,
            ko: &'static str,
        }
        let cases = [
            V {
                ki: "133D114B66EE3D4737720B127900A3C23C783658D2F73FF030A8093B96DD712F",
                label: "735EEDFD8300CD443A7AC18465759CD50FE257D9A19059EF4EFEF5A9AE6E3581A93AD6C7976B93DEA588A7A87BAC8D3F1CDB0AE60D966D3FB9AD16BE",
                context: "1455355D7F7AD491EC57187D4243C36603CEFE682C0C56675C310448395E71600FBBF92CBBC6EF43C8EBE28AD7541FA7440277B8061D4344D788A571",
                ko: "E8068DF95DAC4896B25B46F188DEC662",
            },
            V {
                ki: "4D09B9B29A97F0A632B04024AF98ADB1CF2389E51BCA3A1FC6FE3D77D7BD6BF4",
                label: "8B627B00F4C1C918E77355C8156F0FD778DA52BFF121AE5F2F44EAF4D2754946D0E10D1F18CE3A0176E69C18B7D20B6E0D0BEE5EB5EDFE4BD60E4D92",
                context: "ADCD86BCE72E76F94EE5CBCAA8B01CFDDCEA2ADE575E66ACAE59B34A85036C37AFEEA9C097F0BE74DE2E05D9457ADE5DCEDFF38F1E79C18F268A54C3",
                ko: "0FE983EDB298EDF63CC685A877EECD17CEDE1EA7C486EFEDC070639C8F0A78D3",
            },
        ];
        for v in cases {
            let ki = Vec::from_hex(v.ki).unwrap();
            let label = Vec::from_hex(v.label).unwrap();
            let context = Vec::from_hex(v.context).unwrap();
            let expected = Vec::from_hex(v.ko).unwrap();
            let mut out = vec![0u8; expected.len()];
            kbkdf_hmac_counter(MessageDigest::sha256(), &ki, 1, &label, &context, &mut out)
                .unwrap();
            assert_eq!(out, expected, "KBKDF counter mismatch");
        }
    }

    // Feedback mode with a zero-length IV and L<=h reduces to counter mode
    // (per SP 800-108), giving a useful cross-check.
    #[test]
    fn kbkdf_feedback_matches_counter_when_iv_zero() {
        let ki = Vec::from_hex("133D114B66EE3D4737720B127900A3C23C783658D2F73FF030A8093B96DD712F")
            .unwrap();
        let label = b"label";
        let context = b"context";
        let mut ctr = [0u8; 32];
        let mut fb = [0u8; 32];
        kbkdf_hmac_counter(MessageDigest::sha256(), &ki, 1, label, context, &mut ctr).unwrap();
        kbkdf_hmac_feedback(
            MessageDigest::sha256(),
            &ki,
            1,
            label,
            context,
            &[],
            &mut fb,
        )
        .unwrap();
        assert_eq!(ctr, fb);
    }

    // KISA KBKDF-HMAC-SHA256 double-pipeline (no counter) KAT.
    #[test]
    fn kbkdf_double_pipeline_kat() {
        let ki = Vec::from_hex("5B8B2D635DD0C4AD991260FB86FCC986D09DA8E6FC7647CB4CD198EDE2557946")
            .unwrap();
        let label = Vec::from_hex("27D8367E6E744FA7D5DD7C2A6CF1EF019A91D927BCB02F4D0EA9AECFCFD61DE6A05ED21F2E4E770C10EC0E39F3483361F413A1E24DB4F86F3499BE05").unwrap();
        let context = Vec::from_hex("00CBA3208EC6092EE387C34412E61D1060261D0FA7CB09FFF8AB29988448CE77BD5D945BB8B7E393D646BCB7A374B297FEB536717B60186705BD4B2F").unwrap();
        let expected = Vec::from_hex("47B934EF3934AFB6158B51F68CD9481D3EB21B1AFFEB47F43D9C37EE11DAADB3A2C4475493C14266E083AFC522AD1C33FD0E33289C3D5CF920DF2B619E760501").unwrap();
        let mut out = vec![0u8; expected.len()];
        // counter_bytes = 0 → no-counter 변형.
        kbkdf_hmac_double_pipeline(MessageDigest::sha256(), &ki, 0, &label, &context, &mut out)
            .unwrap();
        assert_eq!(out, expected, "KBKDF double-pipeline mismatch");
    }
}
