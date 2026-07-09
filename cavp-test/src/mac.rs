//! HMAC CAVP 생성기 (KAT).
//!
//! 각 레코드: Key/Msg(16진), Tlen(MAC 바이트 길이). Mac = HMAC(Key, Msg) 를
//! Tlen 바이트로 절단한 값. 다이제스트는 SHA-2/SHA-3/LSH 를 지원한다.
//! 파일명 예: `HMAC_SHA-256_KAT`, `HMAC_SHA3-224_KAT`, `HMAC_LSH-256-224_KAT`.

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::hash::MessageDigest;
use korecrypto::hmac::Hmac;

/// 알고리즘명 → MessageDigest. HMAC 파일은 SHA-2 를 "SHA-224" 로 표기한다
/// (해시 KAT 의 "SHA2-224" 와 다름).
fn lookup(algo: &str) -> Option<MessageDigest> {
    Some(match algo {
        "SHA-224" => MessageDigest::sha224(),
        "SHA-256" => MessageDigest::sha256(),
        "SHA-384" => MessageDigest::sha384(),
        "SHA-512" => MessageDigest::sha512(),
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

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    // "HMAC_<ALGO>_KAT" → ALGO.
    let algo = stem
        .strip_prefix("HMAC_")
        .and_then(|s| s.strip_suffix("_KAT"))
        .unwrap_or("");
    let md = match lookup(algo) {
        Some(m) => m,
        None => {
            return Ok(GenOutcome::Skipped(format!(
                "미지원 HMAC 다이제스트: {algo}"
            )))
        }
    };

    let recs = records(items);
    let mut filled = 0usize;
    for rec in &recs {
        let key = match get(items, rec, "Key") {
            Some(k) => hx(k)?,
            None => continue,
        };
        if get(items, rec, "Mac").is_none() {
            continue;
        }
        let msg = hx(get(items, rec, "Msg").unwrap_or(""))?;
        // Tlen 은 MAC 절단 길이(바이트).
        let tlen: usize = match get(items, rec, "Tlen") {
            Some(t) => t
                .trim()
                .parse()
                .map_err(|e| GenError(format!("Tlen: {e}")))?,
            None => continue,
        };

        let mut h = Hmac::init(&key, &md).map_err(|e| GenError(e.to_string()))?;
        h.update(&msg).map_err(|e| GenError(e.to_string()))?;
        let full = h.finalize().map_err(|e| GenError(e.to_string()))?;
        if tlen > full.len() {
            return Err(GenError(format!("Tlen {tlen} > 다이제스트 {}", full.len())));
        }
        let mac = &full[..tlen];

        if set(items, rec, "Mac", &hex::encode_upper(mac)) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}
