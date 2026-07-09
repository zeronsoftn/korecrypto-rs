//! KBKDF CAVP 생성기 — SP 800-108 / TTAK.KO-12.0272.
//!
//! 지원 모드: Counter(CTR), Feedback(FB; no/use CTR), Double-Pipeline(DP; no/use
//! CTR). PRF: HMAC(SHA2/SHA3/LSH) 및 CMAC(AES/ARIA/SEED/LEA/HIGHT).
//! - HMAC: 검증된 라이브러리 함수(kbkdf_hmac_*)를 사용.
//! - CMAC: 동일한 KISA 구성(fixed = Label||0x00||Context||[L])을 cmac() PRF 로
//!   하니스에서 재현한다(라이브러리 C 구현과 동일 절차).

use crate::parser::{get, records_with_sections, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::cmac::cmac;
use korecrypto::hash::MessageDigest;
use korecrypto::kdf::{kbkdf_hmac_counter, kbkdf_hmac_double_pipeline, kbkdf_hmac_feedback};
use korecrypto::symm::Cipher;

fn md_for(name: &str) -> Option<MessageDigest> {
    Some(match name {
        "SHA2-224" | "SHA224" => MessageDigest::sha224(),
        "SHA2-256" | "SHA256" => MessageDigest::sha256(),
        "SHA2-384" | "SHA384" => MessageDigest::sha384(),
        "SHA2-512" | "SHA512" => MessageDigest::sha512(),
        "SHA3-224" => MessageDigest::sha3_224(),
        "SHA3-256" => MessageDigest::sha3_256(),
        "SHA3-384" => MessageDigest::sha3_384(),
        "SHA3-512" => MessageDigest::sha3_512(),
        "LSH-256-224" => MessageDigest::lsh256_224(),
        "LSH-256-256" => MessageDigest::lsh256_256(),
        "LSH-512-224" => MessageDigest::lsh512_224(),
        "LSH-512-256" => MessageDigest::lsh512_256(),
        "LSH-512-384" => MessageDigest::lsh512_384(),
        "LSH-512-512" => MessageDigest::lsh512_512(),
        _ => return None,
    })
}

/// "CMAC-AES128" 등 PRF 이름 → CMAC 용 블록암호(CBC 변형) Cipher.
fn cmac_cipher(name: &str) -> Option<Cipher> {
    Some(match name {
        "AES128" => Cipher::aes_128_cbc(),
        "AES192" => Cipher::aes_192_cbc(),
        "AES256" => Cipher::aes_256_cbc(),
        "ARIA128" => Cipher::aria_128_cbc(),
        "ARIA192" => Cipher::aria_192_cbc(),
        "ARIA256" => Cipher::aria_256_cbc(),
        "SEED" | "SEED128" => Cipher::seed_cbc(),
        "LEA128" => Cipher::lea_128_cbc(),
        "LEA192" => Cipher::lea_192_cbc(),
        "LEA256" => Cipher::lea_256_cbc(),
        "HIGHT" => Cipher::hight_cbc(),
        _ => return None,
    })
}

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Ctr,
    Fb,
    Dp,
}

/// 출력 길이 L(비트)을 최소 길이 빅엔디안으로 인코딩(KISA addLparam).
fn l_param(l: u32) -> Vec<u8> {
    if l < 0x100 {
        vec![l as u8]
    } else if l < 0x10000 {
        vec![(l >> 8) as u8, l as u8]
    } else if l < 0x100_0000 {
        vec![(l >> 16) as u8, (l >> 8) as u8, l as u8]
    } else {
        vec![(l >> 24) as u8, (l >> 16) as u8, (l >> 8) as u8, l as u8]
    }
}

fn put_counter(ctr: u32, n: usize) -> Vec<u8> {
    (0..n).map(|i| (ctr >> ((n - 1 - i) * 8)) as u8).collect()
}

/// CMAC PRF 기반 KBKDF. 라이브러리 C(kbkdf.cc.inc)와 동일한 절차를 재현한다.
/// fixed = Label || 0x00 || Context || [L].
#[allow(clippy::too_many_arguments)]
fn kbkdf_cmac(
    cipher: Cipher,
    ki: &[u8],
    counter_bytes: usize,
    label: &[u8],
    context: &[u8],
    iv: &[u8],
    mode: Mode,
    out_len: usize,
) -> Result<Vec<u8>, GenError> {
    let prf = |input: &[u8]| cmac(cipher, ki, input).map_err(|e| GenError(e.to_string()));
    // fixed 구성.
    let mut fixed = label.to_vec();
    fixed.push(0x00);
    fixed.extend_from_slice(context);
    fixed.extend(l_param((out_len * 8) as u32));

    let mut out: Vec<u8> = Vec::with_capacity(out_len);
    let mut ctr: u32 = 0;
    match mode {
        Mode::Dp => {
            let mut a = fixed.clone();
            let mut first = true;
            while out.len() < out_len {
                ctr += 1;
                a = if first {
                    first = false;
                    prf(&fixed)?
                } else {
                    prf(&a)?
                };
                let mut input = a.clone();
                input.extend(put_counter(ctr, counter_bytes));
                input.extend_from_slice(&fixed);
                out.extend(prf(&input)?);
            }
        }
        Mode::Ctr | Mode::Fb => {
            let feedback = mode == Mode::Fb;
            let mut prev: Vec<u8> = if feedback { iv.to_vec() } else { Vec::new() };
            while out.len() < out_len {
                ctr += 1;
                let mut input = Vec::new();
                if feedback && !prev.is_empty() {
                    input.extend_from_slice(&prev);
                }
                input.extend(put_counter(ctr, counter_bytes));
                input.extend_from_slice(&fixed);
                let block = prf(&input)?;
                if feedback {
                    prev = block.clone();
                }
                out.extend(block);
            }
        }
    }
    out.truncate(out_len);
    Ok(out)
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    // 모드 판별.
    let mode = if stem.starts_with("KDF_(CTR)") {
        Mode::Ctr
    } else if stem.contains("(FB)") {
        Mode::Fb
    } else if stem.contains("(DP)") {
        Mode::Dp
    } else {
        return Ok(GenOutcome::Skipped("KDF 모드 판별 실패".into()));
    };
    // 카운터 사용 여부: CTR 모드는 항상 사용, FB/DP 는 "(use CTR)" 일 때만.
    let use_counter = mode == Mode::Ctr || stem.contains("(use CTR)");

    // PRF/RLEN 은 파일 안에 여러 `[...]` 섹션으로 반복되므로(RLEN 8/16/24/32),
    // 각 레코드가 속한 섹션에서 읽는다.
    let recs = records_with_sections(items);
    let mut filled = 0;
    for (rec, sect) in &recs {
        // RLEN(비트) → counter_bytes. 카운터 미사용 시 0.
        let rlen: u32 = sect.get("RLEN").and_then(|s| s.parse().ok()).unwrap_or(8);
        let counter_bytes = if use_counter { (rlen / 8) as usize } else { 0 };

        // PRF: "HMAC-<해시>" 또는 "CMAC-<블록암호>".
        let prf = sect.get("PRF").cloned().unwrap_or_default();
        let (is_hmac, md, cipher) = if let Some(h) = prf.strip_prefix("HMAC-") {
            match md_for(h) {
                Some(m) => (true, Some(m), None),
                None => return Ok(GenOutcome::Skipped(format!("미지원 KDF PRF: {prf}"))),
            }
        } else if let Some(c) = prf.strip_prefix("CMAC-") {
            match cmac_cipher(c) {
                Some(cp) => (false, None, Some(cp)),
                None => return Ok(GenOutcome::Skipped(format!("미지원 KDF PRF: {prf}"))),
            }
        } else {
            return Ok(GenOutcome::Skipped(format!("미지원 KDF PRF: {prf}")));
        };

        let l_bits: usize = match get(items, rec, "L") {
            Some(v) => v.trim().parse().map_err(|_| GenError("L 파싱".into()))?,
            None => continue,
        };
        let ki = hx(get(items, rec, "KI").unwrap_or(""))?;
        let label = hx(get(items, rec, "Label").unwrap_or(""))?;
        let context = hx(get(items, rec, "Context").unwrap_or(""))?;
        let iv = hx(get(items, rec, "IV").unwrap_or(""))?;
        let out_len = l_bits / 8;
        let mut out = vec![0u8; out_len];

        if is_hmac {
            let md = md.unwrap();
            let cb = counter_bytes as u32;
            match mode {
                Mode::Ctr => {
                    kbkdf_hmac_counter(md, &ki, cb, &label, &context, &mut out)
                        .map_err(|e| GenError(e.to_string()))?;
                }
                Mode::Fb => {
                    kbkdf_hmac_feedback(md, &ki, cb, &label, &context, &iv, &mut out)
                        .map_err(|e| GenError(e.to_string()))?;
                }
                Mode::Dp => {
                    kbkdf_hmac_double_pipeline(md, &ki, cb, &label, &context, &mut out)
                        .map_err(|e| GenError(e.to_string()))?;
                }
            }
        } else {
            out = kbkdf_cmac(
                cipher.unwrap(),
                &ki,
                counter_bytes,
                &label,
                &context,
                &iv,
                mode,
                out_len,
            )?;
        }

        if set(items, rec, "KO", &hex::encode_upper(&out)) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}
