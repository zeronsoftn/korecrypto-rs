//! ECDH 키합의 CAVP 생성기 — 소수체 곡선(P-224/P-256) KAKAT/KPG/PKV.
//!
//! - KAKAT: 당사자 B: 개인키 rB, 상대(A) 공개점 KTA1 → 공유점 KAB = rB·KTA1.
//! - KPG: 무작위 키쌍 생성(d, Qx, Qy).
//! - PKV: 공개점 유효성(곡선 위의 점) → Result P/F.
//!
//! 이진체 곡선(B/K-233/283)은 미지원으로 건너뛴다.

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::bn::{BigNum, BigNumContext};
use korecrypto::ec::{EcGroup, EcKey, EcPoint};
use korecrypto::nid::Nid;

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
        _ => return None,
    })
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    // "ECDH_(P-256)_KAKAT".
    let open = stem.find('(').ok_or_else(|| GenError("(없음".into()))?;
    let close = stem.find(')').ok_or_else(|| GenError(")없음".into()))?;
    let cname = &stem[open + 1..close];
    let (nid, coord) = match curve(cname) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped(format!("미지원 곡선(이진체): {cname}"))),
    };
    let group = EcGroup::from_curve_name(nid).map_err(|e| GenError(e.to_string()))?;
    let mut ctx = BigNumContext::new().map_err(|e| GenError(e.to_string()))?;

    // KPG: 무작위 키쌍 생성(d, Qx, Qy).
    if stem.ends_with("_KPG") {
        let recs = records(items);
        let mut filled = 0;
        for rec in &recs {
            if get(items, rec, "d").is_none() {
                continue;
            }
            let key = EcKey::generate(&group).map_err(|e| GenError(e.to_string()))?;
            let d = key
                .private_key()
                .to_vec_padded(coord)
                .map_err(|e| GenError(e.to_string()))?;
            let mut x = BigNum::new().map_err(|e| GenError(e.to_string()))?;
            let mut y = BigNum::new().map_err(|e| GenError(e.to_string()))?;
            key.public_key()
                .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
                .map_err(|e| GenError(e.to_string()))?;
            let qx = x
                .to_vec_padded(coord)
                .map_err(|e| GenError(e.to_string()))?;
            let qy = y
                .to_vec_padded(coord)
                .map_err(|e| GenError(e.to_string()))?;
            filled += set(items, rec, "d", &hex::encode_upper(&d)) as usize;
            filled += set(items, rec, "Qx", &hex::encode_upper(&qx)) as usize;
            filled += set(items, rec, "Qy", &hex::encode_upper(&qy)) as usize;
        }
        return Ok(GenOutcome::Generated(filled));
    }

    // PKV: 공개점 유효성(곡선 위의 점인지) → Result P/F.
    if stem.ends_with("_PKV") {
        let recs = records(items);
        let mut filled = 0;
        for rec in &recs {
            let qx = match get(items, rec, "Qx") {
                Some(v) => bn(v)?,
                None => continue,
            };
            let qy = bn(get(items, rec, "Qy").unwrap_or("0"))?;
            let ok = EcKey::from_public_key_affine_coordinates(&group, &qx, &qy)
                .map(|k| k.check_key().is_ok())
                .unwrap_or(false);
            filled += set(items, rec, "Result", if ok { "P" } else { "F" }) as usize;
        }
        return Ok(GenOutcome::Generated(filled));
    }

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        let rb = match get(items, rec, "rB") {
            Some(v) => bn(v)?,
            None => continue,
        };
        let ax = bn(get(items, rec, "KTA1x").unwrap_or("0"))?;
        let ay = bn(get(items, rec, "KTA1y").unwrap_or("0"))?;

        // 상대 공개점 → EcPoint.
        let peer = EcKey::from_public_key_affine_coordinates(&group, &ax, &ay)
            .map_err(|e| GenError(e.to_string()))?;
        // KAB = rB · KTA1.
        let mut kab = EcPoint::new(&group).map_err(|e| GenError(e.to_string()))?;
        kab.mul(&group, peer.public_key(), &rb, &mut ctx)
            .map_err(|e| GenError(e.to_string()))?;
        let mut x = BigNum::new().map_err(|e| GenError(e.to_string()))?;
        let mut y = BigNum::new().map_err(|e| GenError(e.to_string()))?;
        kab.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
            .map_err(|e| GenError(e.to_string()))?;

        filled += set(
            items,
            rec,
            "KABx",
            &hex::encode_upper(
                &x.to_vec_padded(coord)
                    .map_err(|e| GenError(e.to_string()))?,
            ),
        ) as usize;
        filled += set(
            items,
            rec,
            "KABy",
            &hex::encode_upper(
                &y.to_vec_padded(coord)
                    .map_err(|e| GenError(e.to_string()))?,
            ),
        ) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}
