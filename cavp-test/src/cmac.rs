//! CMAC CAVP 생성기 (Gen / Ver).
//!
//! 라이브러리 `korecrypto::cmac`(CMAC_CTX, CBC EVP_CIPHER)로 태그를 계산한다.
//! - Gen: T = CMAC(K, M) 를 Tlen 비트로 절단.
//! - Ver: 계산한 태그와 주어진 T 를 비교해 "VALID"/"INVALID" 로 판정.
//!
//! Tlen 은 비트 단위. AES/ARIA/LEA/SEED/HIGHT 지원.

use crate::parser::{get, records, replace_raw, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::cmac::cmac;
use korecrypto::symm::Cipher;

/// 알고리즘명 → CMAC 하부 블록암호(CBC EVP_CIPHER).
fn lookup(algo: &str) -> Option<Cipher> {
    Some(match algo {
        "AES-128" => Cipher::aes_128_cbc(),
        "AES-192" => Cipher::aes_192_cbc(),
        "AES-256" => Cipher::aes_256_cbc(),
        "ARIA-128" => Cipher::aria_128_cbc(),
        "ARIA-192" => Cipher::aria_192_cbc(),
        "ARIA-256" => Cipher::aria_256_cbc(),
        "SEED-128" => Cipher::seed_cbc(),
        "LEA-128" => Cipher::lea_128_cbc(),
        "LEA-192" => Cipher::lea_192_cbc(),
        "LEA-256" => Cipher::lea_256_cbc(),
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

/// 파일명 "CMAC_<ALGO>_<Gen|Ver>" → (ALGO, 시험유형).
fn parse_name(stem: &str) -> Option<(String, String)> {
    let rest = stem.strip_prefix("CMAC_")?;
    let us = rest.rfind('_')?;
    Some((rest[..us].to_string(), rest[us + 1..].to_string()))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (algo, ttype) = match parse_name(stem) {
        Some(t) => t,
        None => return Ok(GenOutcome::Skipped("CMAC 파일명 파싱 실패".into())),
    };
    let cipher = match lookup(&algo) {
        Some(c) => c,
        None => return Ok(GenOutcome::Skipped(format!("미지원 CMAC 암호: {algo}"))),
    };

    let recs = records(items);
    let mut filled = 0usize;
    for rec in &recs {
        let key = match get(items, rec, "K") {
            Some(k) => hx(k)?,
            None => continue,
        };
        let msg = hx(get(items, rec, "M").unwrap_or(""))?;
        let tlen_bits: usize = match get(items, rec, "Tlen") {
            Some(t) => t
                .trim()
                .parse()
                .map_err(|e| GenError(format!("Tlen: {e}")))?,
            None => continue,
        };
        let tbytes = tlen_bits / 8;

        let full = cmac(cipher, &key, &msg).map_err(|e| GenError(e.to_string()))?;
        if tbytes > full.len() {
            return Err(GenError(format!("Tlen {tbytes}B > 블록 {}", full.len())));
        }
        let tag = &full[..tbytes];

        match ttype.as_str() {
            "Gen" => {
                if set(items, rec, "T", &hex::encode_upper(tag)) {
                    filled += 1;
                }
            }
            "Ver" => {
                let given = hx(get(items, rec, "T").unwrap_or(""))?;
                let verdict = if given == tag { "VALID" } else { "INVALID" };
                if replace_raw(items, rec, "VALID or INVALID", verdict) {
                    filled += 1;
                }
            }
            other => return Ok(GenOutcome::Skipped(format!("미지원 CMAC 유형: {other}"))),
        }
    }
    Ok(GenOutcome::Generated(filled))
}
