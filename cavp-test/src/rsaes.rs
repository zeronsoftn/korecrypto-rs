//! RSAES-OAEP CAVP 생성기.
//!
//! 시험유형:
//! - DET: 개인키(n,e,d)로 암호문 C 를 복호화하여 평문 M 산출(결정적).
//! - ENT: 공개키(n,e)로 평문 M 을 암호화하여 C 산출(OAEP 무작위 패딩 →
//!   검증기는 자신의 개인키로 복호화해 일치 확인).
//! - KGT: RSA 키쌍(n,e,q,p,d) 생성.

use crate::parser::{get, records, Item};
use crate::{GenError, GenOutcome};
use korecrypto::bn::BigNum;
use korecrypto::hash::MessageDigest;
use korecrypto::pkey::PKey;
use korecrypto::rsa::{Rsa, RsaPrivateKeyBuilder};

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}
fn bn_hex(s: &str) -> Result<BigNum, GenError> {
    BigNum::from_slice(&hx(s)?).map_err(|e| GenError(e.to_string()))
}

fn md_for(name: &str) -> Option<MessageDigest> {
    Some(match name {
        "SHA-224" | "SHA2-224" => MessageDigest::sha224(),
        "SHA-256" | "SHA2-256" => MessageDigest::sha256(),
        "SHA-384" | "SHA2-384" => MessageDigest::sha384(),
        "SHA-512" | "SHA2-512" => MessageDigest::sha512(),
        _ => return None,
    })
}

/// 헤더(Field/Raw)에서 "key = value" 첫 값을 읽는다.
fn header(items: &[Item], key: &str) -> Option<String> {
    let pfx = format!("{key} = ");
    for it in items {
        match it {
            Item::Field { key: k, value, .. } if k == key => return Some(value.clone()),
            Item::Raw(s) => {
                if let Some(v) = s.trim().strip_prefix(&pfx) {
                    return Some(v.trim().to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// "RSAES_(2048)(65537)_SHA-224_DET" → (bits, hash, type).
fn parse(stem: &str) -> Option<(u32, String, String)> {
    let open = stem.find('(')?;
    let close = stem.find(')')?;
    let bits: u32 = stem[open + 1..close].parse().ok()?;
    let rest = &stem[close + 1..];
    // 두 번째 괄호(e)는 건너뛴다.
    let after_e = rest.find(')').map(|i| &rest[i + 1..]).unwrap_or(rest);
    let tail = after_e.trim_start_matches('_');
    let mut parts = tail.rsplitn(2, '_');
    let ttype = parts.next()?.to_string();
    let hash = parts.next()?.to_string();
    Some((bits, hash, ttype))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (bits, hash, ttype) = match parse(stem) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped("RSAES 파일명 파싱 실패".into())),
    };
    let md = match md_for(&hash) {
        Some(m) => m,
        None => return Ok(GenOutcome::Skipped(format!("미지원 RSAES 해시: {hash}"))),
    };

    match ttype.as_str() {
        "DET" => det(items, md),
        "ENT" => ent(items, md),
        "KGT" => kgt(items, bits),
        other => Ok(GenOutcome::Skipped(format!("미지원 RSAES 유형: {other}"))),
    }
}

/// DET: (n,e,d) 개인키로 각 C 를 복호화 → M.
fn det(items: &mut [Item], md: MessageDigest) -> Result<GenOutcome, GenError> {
    let n = bn_hex(&header(items, "n").ok_or_else(|| GenError("n 미발견".into()))?)?;
    // e 는 10진수.
    let e_dec = header(items, "e").ok_or_else(|| GenError("e 미발견".into()))?;
    let e = BigNum::from_dec_str(e_dec.trim()).map_err(|e| GenError(e.to_string()))?;
    let d = bn_hex(&header(items, "d").ok_or_else(|| GenError("d 미발견".into()))?)?;
    let rsa = RsaPrivateKeyBuilder::new(n, e, d)
        .map_err(|e| GenError(e.to_string()))?
        .build();
    let pkey = PKey::from_rsa(rsa).map_err(|e| GenError(e.to_string()))?;

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        let c = match get(items, rec, "C") {
            Some(v) => hx(v)?,
            None => continue,
        };
        if get(items, rec, "M").map(|v| v.contains('?')) != Some(true) {
            continue;
        }
        let label = hx(get(items, rec, "LABEL").unwrap_or(""))?;
        let m = pkey
            .rsa_oaep_decrypt(md, &label, &c)
            .map_err(|e| GenError(e.to_string()))?;
        filled += crate::parser::set(items, rec, "M", &hex::encode_upper(&m)) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}

/// ENT: (n,e) 공개키로 각 M 을 암호화 → C.
fn ent(items: &mut [Item], md: MessageDigest) -> Result<GenOutcome, GenError> {
    let n = bn_hex(&header(items, "n").ok_or_else(|| GenError("n 미발견".into()))?)?;
    let e_dec = header(items, "e").ok_or_else(|| GenError("e 미발견".into()))?;
    let e = BigNum::from_dec_str(e_dec.trim()).map_err(|e| GenError(e.to_string()))?;
    let rsa = Rsa::from_public_components(n, e).map_err(|e| GenError(e.to_string()))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| GenError(e.to_string()))?;

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        let m = match get(items, rec, "M") {
            Some(v) => hx(v)?,
            None => continue,
        };
        if get(items, rec, "C").map(|v| v.contains('?')) != Some(true) {
            continue;
        }
        let label = hx(get(items, rec, "LABEL").unwrap_or(""))?;
        let c = pkey
            .rsa_oaep_encrypt(md, &label, &m)
            .map_err(|e| GenError(e.to_string()))?;
        filled += crate::parser::set(items, rec, "C", &hex::encode_upper(&c)) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}

/// KGT: RSA 키쌍 생성(n,e,q,p,d).
fn kgt(items: &mut [Item], bits: u32) -> Result<GenOutcome, GenError> {
    use crate::parser::set;
    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        if get(items, rec, "n").map(|v| v.contains('?')) != Some(true) {
            continue;
        }
        let rsa = Rsa::generate(bits).map_err(|e| GenError(e.to_string()))?;
        let n = rsa.n().to_vec();
        let e = rsa.e().to_vec();
        let d = rsa.d().to_vec();
        let p = rsa.p().ok_or_else(|| GenError("p 없음".into()))?.to_vec();
        let q = rsa.q().ok_or_else(|| GenError("q 없음".into()))?.to_vec();
        filled += set(items, rec, "n", &hex::encode_upper(&n)) as usize;
        filled += set(items, rec, "e", &hex::encode_upper(&e)) as usize;
        filled += set(items, rec, "q", &hex::encode_upper(&q)) as usize;
        filled += set(items, rec, "p", &hex::encode_upper(&p)) as usize;
        filled += set(items, rec, "d", &hex::encode_upper(&d)) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}
