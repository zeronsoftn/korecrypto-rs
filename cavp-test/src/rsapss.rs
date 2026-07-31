//! RSA-PSS CAVP 생성기 — 서명검증(SVT), 서명생성(SGT), 키생성(KPG).
//!
//! SVT 는 결정적. SGT 는 키쌍을 생성해 각 M 에 PSS 서명(검증기는 솔트 자동
//! 복원으로 검증). KPG 는 RSA 키쌍(n,e,d,p,q)을 생성한다.

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::bn::BigNum;
use korecrypto::hash::MessageDigest;
use korecrypto::pkey::PKey;
use korecrypto::rsa::{Padding, Rsa};
use korecrypto::sign::{RsaPssSaltlen, Signer, Verifier};

/// "RSA-PSS_(2048)(65537)_SHA-256_SGT" → mod 비트 길이.
fn parse_bits(stem: &str) -> Option<u32> {
    let open = stem.find('(')?;
    let close = stem.find(')')?;
    stem[open + 1..close].parse().ok()
}

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}
fn bn(s: &str) -> Result<BigNum, GenError> {
    BigNum::from_slice(&hx(s)?).map_err(|e| GenError(e.to_string()))
}

fn md_for(name: &str) -> Option<MessageDigest> {
    Some(match name {
        "SHA-224" => MessageDigest::sha224(),
        "SHA-256" => MessageDigest::sha256(),
        "SHA-384" => MessageDigest::sha384(),
        "SHA-512" => MessageDigest::sha512(),
        _ => return None,
    })
}

fn header(items: &[Item], key: &str) -> Option<String> {
    let pfx = format!("{key} = ");
    for it in items {
        if let Item::Field { key: k, value, .. } = it {
            if k == key {
                return Some(value.clone());
            }
        }
        if let Item::Raw(s) = it {
            if let Some(v) = s.trim().strip_prefix(&pfx) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    if stem.ends_with("_SGT") {
        return sgt(stem, items);
    }
    if stem.ends_with("_KPG") {
        return kpg(stem, items);
    }
    if !stem.ends_with("_SVT") {
        return Ok(GenOutcome::Skipped("RSA-PSS: 미지원 시험유형".into()));
    }
    // HashAlg 헤더.
    let halg = header(items, "HashAlg").unwrap_or_default();
    let md = match md_for(&halg) {
        Some(m) => m,
        None => return Ok(GenOutcome::Skipped(format!("미지원 해시: {halg}"))),
    };

    let recs = records(items);
    let mut filled = 0;
    // n, v(=e) 는 파일 상단(헤더 레코드)에 1회 등장.
    let mut n: Option<BigNum> = None;
    let mut e: Option<BigNum> = None;
    for rec in &recs {
        if let Some(v) = get(items, rec, "n") {
            n = Some(bn(v)?);
        }
        if let Some(v) = get(items, rec, "v") {
            e = Some(bn(v)?);
        }
        // 검증 레코드: M, S, Result.
        let m = match get(items, rec, "M") {
            Some(v) => hx(v)?,
            None => continue,
        };
        let s = hx(get(items, rec, "S").unwrap_or(""))?;
        let (nn, ee) = match (&n, &e) {
            (Some(n), Some(e)) => (
                BigNum::from_slice(&n.to_vec()).unwrap(),
                BigNum::from_slice(&e.to_vec()).unwrap(),
            ),
            _ => continue,
        };
        let rsa = Rsa::from_public_components(nn, ee).map_err(|e| GenError(e.to_string()))?;
        let pkey = PKey::from_rsa(rsa).map_err(|e| GenError(e.to_string()))?;

        let verdict = (|| -> Result<bool, GenError> {
            let mut v = Verifier::new(md, &pkey).map_err(|e| GenError(e.to_string()))?;
            v.set_rsa_padding(Padding::PKCS1_PSS)
                .map_err(|e| GenError(e.to_string()))?;
            // 검증 시 솔트 길이 자동 복원(-2).
            v.set_rsa_pss_saltlen(RsaPssSaltlen::MAXIMUM_LENGTH)
                .map_err(|e| GenError(e.to_string()))?;
            v.update(&m).map_err(|e| GenError(e.to_string()))?;
            Ok(v.verify(&s).unwrap_or(false))
        })()
        .unwrap_or(false);

        if set(items, rec, "Result", if verdict { "P" } else { "F" }) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}

fn md_from_hashalg(items: &[Item]) -> Option<MessageDigest> {
    md_for(&header(items, "HashAlg").unwrap_or_default())
}

/// SGT: RSA 키쌍을 1회 생성하고(n 출력), 각 M 에 PSS 서명 → S.
fn sgt(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let bits = parse_bits(stem).unwrap_or(2048);
    let md = match md_from_hashalg(items) {
        Some(m) => m,
        None => return Ok(GenOutcome::Skipped("RSA-PSS SGT: 해시 미상".into())),
    };
    let rsa = Rsa::generate(bits).map_err(|e| GenError(e.to_string()))?;
    let n = rsa.n().to_vec();
    let pkey = PKey::from_rsa(rsa).map_err(|e| GenError(e.to_string()))?;

    let recs = records(items);
    let mut filled = 0;
    // n 은 헤더 레코드에 1회 등장.
    for rec in &recs {
        if get(items, rec, "n").map(|v| v.contains('?')) == Some(true) {
            filled += set(items, rec, "n", &hex::encode_upper(&n)) as usize;
        }
        let m = match get(items, rec, "M") {
            Some(v) => hx(v)?,
            None => continue,
        };
        if get(items, rec, "S").map(|v| v.contains('?')) != Some(true) {
            continue;
        }
        let mut signer = Signer::new(md, &pkey).map_err(|e| GenError(e.to_string()))?;
        signer
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| GenError(e.to_string()))?;
        // 솔트 길이 = 다이제스트 길이(표준값). 검증기는 자동 복원으로 검증.
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| GenError(e.to_string()))?;
        signer.update(&m).map_err(|e| GenError(e.to_string()))?;
        let s = signer.sign_to_vec().map_err(|e| GenError(e.to_string()))?;
        filled += set(items, rec, "S", &hex::encode_upper(&s)) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}

/// KPG: RSA 키쌍을 생성한다. 레코드 필드 v(=e), p1(=p), p2(=q), n, s(=d).
fn kpg(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let bits = parse_bits(stem)
        .or_else(|| header(items, "|n|").and_then(|s| s.parse().ok()))
        .unwrap_or(2048);
    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        if get(items, rec, "n").map(|v| v.contains('?')) != Some(true) {
            continue;
        }
        let rsa = Rsa::generate(bits).map_err(|e| GenError(e.to_string()))?;
        let v = rsa.e().to_vec();
        let p1 = rsa.p().ok_or_else(|| GenError("p 없음".into()))?.to_vec();
        let p2 = rsa.q().ok_or_else(|| GenError("q 없음".into()))?.to_vec();
        let n = rsa.n().to_vec();
        let s = rsa.d().to_vec();
        filled += set(items, rec, "v", &hex::encode_upper(&v)) as usize;
        filled += set(items, rec, "p1", &hex::encode_upper(&p1)) as usize;
        filled += set(items, rec, "p2", &hex::encode_upper(&p2)) as usize;
        filled += set(items, rec, "n", &hex::encode_upper(&n)) as usize;
        filled += set(items, rec, "s", &hex::encode_upper(&s)) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}
