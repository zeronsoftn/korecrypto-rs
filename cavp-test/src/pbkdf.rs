//! PBKDF CAVP 생성기 — PBKDF2(HMAC PRF).
//!
//! Password 는 ASCII 문자열(원문 바이트), Salt 는 16진수, KLen 은 비트.

use crate::parser::{get, records_with_sections, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::hash::MessageDigest;
use korecrypto::pkcs5::pbkdf2_hmac;

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

pub fn generate(items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let recs = records_with_sections(items);
    let mut filled = 0;
    for (rec, sect) in &recs {
        // PRF·Iteration 은 레코드가 속한 섹션에서 가져온다.
        let prf = sect.get("PRF").cloned().unwrap_or_default();
        let hashname = prf.strip_prefix("HMAC-").unwrap_or("");
        let md = match md_for(hashname) {
            Some(m) => m,
            None => continue, // PRF 미설정 섹션(헤더만 있는 위치)은 건너뜀
        };
        let iter: usize = match sect.get("Iteration").and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => continue,
        };
        let pass = match get(items, rec, "Password") {
            Some(v) => v.as_bytes().to_vec(), // ASCII 문자열 원문
            None => continue,
        };
        let salt = hex::decode(get(items, rec, "Salt").unwrap_or("").trim())
            .map_err(|e| GenError(format!("Salt hex: {e}")))?;
        let klen_bits: usize = get(items, rec, "KLen")
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| GenError("KLen 파싱".into()))?;
        let mut mk = vec![0u8; klen_bits / 8];
        pbkdf2_hmac(&pass, &salt, iter, md, &mut mk).map_err(|e| GenError(e.to_string()))?;
        if set(items, rec, "MK", &hex::encode_upper(&mk)) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}
