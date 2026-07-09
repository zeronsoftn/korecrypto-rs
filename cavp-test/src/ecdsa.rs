//! ECDSA CAVP 생성기 — 소수체 곡선(P-224/256/384/521).
//!
//! 시험유형 KPG/PKV/SGT/SVT. 이진체 곡선(B/K-233/283)은 미지원으로 건너뛴다.

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::bn::{BigNum, BigNumContext};
use korecrypto::ec::{EcGroup, EcKey};
use korecrypto::ecdsa::EcdsaSig;
use korecrypto::hash::{hash, MessageDigest};
use korecrypto::nid::Nid;
use korecrypto::pkey::Private;

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}
fn bn(s: &str) -> Result<BigNum, GenError> {
    BigNum::from_slice(&hx(s)?).map_err(|e| GenError(e.to_string()))
}

fn curve(name: &str) -> Option<(Nid, usize)> {
    Some(match name {
        "P-224" => (Nid::SECP224R1, 28),
        "P-256" => (Nid::X9_62_PRIME256V1, 32),
        "P-384" => (Nid::SECP384R1, 48),
        "P-521" => (Nid::SECP521R1, 66),
        _ => return None,
    })
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

/// "ECDSA_(P-256)_SHA-256_SGT" → (curve, hash, type).
fn parse_name(stem: &str) -> Option<(String, String, String)> {
    let open = stem.find('(')?;
    let close = stem.find(')')?;
    let c = stem[open + 1..close].to_string();
    let rest = stem[close + 1..].trim_start_matches('_');
    let mut it = rest.rsplitn(2, '_');
    let t = it.next()?.to_string();
    let h = it.next()?.to_string();
    Some((c, h, t))
}

fn pub_coords(
    group: &EcGroup,
    key: &EcKey<Private>,
    coord: usize,
    ctx: &mut BigNumContext,
) -> Result<(Vec<u8>, Vec<u8>), GenError> {
    let mut x = BigNum::new().map_err(|e| GenError(e.to_string()))?;
    let mut y = BigNum::new().map_err(|e| GenError(e.to_string()))?;
    key.public_key()
        .affine_coordinates_gfp(group, &mut x, &mut y, ctx)
        .map_err(|e| GenError(e.to_string()))?;
    Ok((
        x.to_vec_padded(coord)
            .map_err(|e| GenError(e.to_string()))?,
        y.to_vec_padded(coord)
            .map_err(|e| GenError(e.to_string()))?,
    ))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (cname, hname, ttype) = match parse_name(stem) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped("ECDSA 파일명 파싱 실패".into())),
    };
    let (nid, coord) = match curve(&cname) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped(format!("미지원 곡선(이진체): {cname}"))),
    };
    let group = EcGroup::from_curve_name(nid).map_err(|e| GenError(e.to_string()))?;
    let md = md_for(&hname);
    let mut ctx = BigNumContext::new().map_err(|e| GenError(e.to_string()))?;

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        match ttype.as_str() {
            "KPG" => {
                // ECDSA KPG 의 개인키 필드는 "X"(빅엔디안). 공개키는 Yx/Yy.
                if get(items, rec, "X").is_none() {
                    continue;
                }
                let key = EcKey::generate(&group).map_err(|e| GenError(e.to_string()))?;
                let d = key
                    .private_key()
                    .to_vec_padded(coord)
                    .map_err(|e| GenError(e.to_string()))?;
                let (yx, yy) = pub_coords(&group, &key, coord, &mut ctx)?;
                filled += set(items, rec, "X", &hex::encode_upper(&d)) as usize;
                filled += set(items, rec, "Yx", &hex::encode_upper(&yx)) as usize;
                filled += set(items, rec, "Yy", &hex::encode_upper(&yy)) as usize;
            }
            "PKV" => {
                let x = match get(items, rec, "Yx") {
                    Some(v) => bn(v)?,
                    None => continue,
                };
                let y = bn(get(items, rec, "Yy").unwrap_or("0"))?;
                let ok = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
                    .map(|k| k.check_key().is_ok())
                    .unwrap_or(false);
                filled += set(items, rec, "Result", if ok { "P" } else { "F" }) as usize;
            }
            "SGT" => {
                let m = match get(items, rec, "M") {
                    Some(v) => hx(v)?,
                    None => continue,
                };
                let md = md.ok_or_else(|| GenError("미지원 해시".into()))?;
                let digest = hash(md, &m).map_err(|e| GenError(e.to_string()))?;
                let key = EcKey::generate(&group).map_err(|e| GenError(e.to_string()))?;
                let (yx, yy) = pub_coords(&group, &key, coord, &mut ctx)?;
                let sig = EcdsaSig::sign(&digest, &key).map_err(|e| GenError(e.to_string()))?;
                let r = sig
                    .r()
                    .to_vec_padded(coord)
                    .map_err(|e| GenError(e.to_string()))?;
                let s = sig
                    .s()
                    .to_vec_padded(coord)
                    .map_err(|e| GenError(e.to_string()))?;
                filled += set(items, rec, "Yx", &hex::encode_upper(&yx)) as usize;
                filled += set(items, rec, "Yy", &hex::encode_upper(&yy)) as usize;
                filled += set(items, rec, "R", &hex::encode_upper(&r)) as usize;
                filled += set(items, rec, "S", &hex::encode_upper(&s)) as usize;
            }
            "SVT" => {
                let m = match get(items, rec, "M") {
                    Some(v) => hx(v)?,
                    None => continue,
                };
                let md = md.ok_or_else(|| GenError("미지원 해시".into()))?;
                let digest = hash(md, &m).map_err(|e| GenError(e.to_string()))?;
                let x = bn(get(items, rec, "Yx").unwrap_or("0"))?;
                let y = bn(get(items, rec, "Yy").unwrap_or("0"))?;
                let r = bn(get(items, rec, "R").unwrap_or("0"))?;
                let s = bn(get(items, rec, "S").unwrap_or("0"))?;
                let verdict = match EcKey::from_public_key_affine_coordinates(&group, &x, &y) {
                    Ok(pk) => match EcdsaSig::from_private_components(r, s) {
                        Ok(sig) => sig.verify(&digest, &pk).unwrap_or(false),
                        Err(_) => false,
                    },
                    Err(_) => false,
                };
                filled += set(items, rec, "Result", if verdict { "P" } else { "F" }) as usize;
            }
            other => return Ok(GenOutcome::Skipped(format!("미지원 시험유형: {other}"))),
        }
    }
    Ok(GenOutcome::Generated(filled))
}
