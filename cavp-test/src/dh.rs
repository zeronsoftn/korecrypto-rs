//! DH(유한체 디피-헬만) 키합의 CAVP 생성기.
//!
//! 당사자 B 관점: 개인키 rB, 공개키 KTB1 = G^rB mod P, 상대 공개키 KTA1 →
//! 공유비밀 KAB = KTA1^rB mod P. 출력은 P 바이트 길이로 0-패딩.

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::bn::{BigNum, BigNumContext};
use korecrypto::kcdsa::KcdsaKey;
use std::cmp::Ordering;

/// "|P| = 2048" 같은 헤더에서 정수값을 읽는다(Field/Raw 모두 대응).
fn header_int(items: &[Item], key: &str) -> Option<usize> {
    let pfx = format!("{key} = ");
    for it in items {
        match it {
            Item::Field { key: k, value, .. } if k == key => return value.trim().parse().ok(),
            Item::Raw(s) => {
                if let Some(v) = s.trim().strip_prefix(&pfx) {
                    return v.trim().parse().ok();
                }
            }
            _ => {}
        }
    }
    None
}

fn bn(s: &str) -> Result<BigNum, GenError> {
    BigNum::from_slice(&hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))?)
        .map_err(|e| GenError(e.to_string()))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    // PVT(파라미터 검증)은 주어진 (P,Q,G)의 소수성·생성원 판정 → 검증 로직.
    if stem.ends_with("_PVT") {
        return pvt(items);
    }
    // PGT(파라미터 생성): KCDSA 와 동일한 PQG 절차로 (P,Q,G)+증거값 생성.
    if stem.ends_with("_PGT") {
        return pgt(items);
    }
    // 키합의 KAT 만 지원.
    if !stem.ends_with("_KAT") {
        return Ok(GenOutcome::Skipped("DH 시험유형 미지원".into()));
    }
    let recs = records(items);
    let mut ctx = BigNumContext::new().map_err(|e| GenError(e.to_string()))?;
    let mut filled = 0;
    for rec in &recs {
        let p = match get(items, rec, "P") {
            Some(v) => bn(v)?,
            None => continue,
        };
        let g = bn(get(items, rec, "G").unwrap_or("0"))?;
        let rb = bn(get(items, rec, "rB").unwrap_or("0"))?;
        let plen = p.num_bytes() as usize;

        // KTB1 = G^rB mod P
        if get(items, rec, "KTB1")
            .map(|v| v.contains('?'))
            .unwrap_or(false)
        {
            let mut ktb1 = BigNum::new().map_err(|e| GenError(e.to_string()))?;
            ktb1.mod_exp(&g, &rb, &p, &mut ctx)
                .map_err(|e| GenError(e.to_string()))?;
            let v = ktb1
                .to_vec_padded(plen)
                .map_err(|e| GenError(e.to_string()))?;
            filled += set(items, rec, "KTB1", &hex::encode_upper(&v)) as usize;
        }
        // KAB = KTA1^rB mod P
        if get(items, rec, "KAB")
            .map(|v| v.contains('?'))
            .unwrap_or(false)
        {
            let kta1 = bn(get(items, rec, "KTA1").unwrap_or("0"))?;
            let mut kab = BigNum::new().map_err(|e| GenError(e.to_string()))?;
            kab.mod_exp(&kta1, &rb, &p, &mut ctx)
                .map_err(|e| GenError(e.to_string()))?;
            let v = kab
                .to_vec_padded(plen)
                .map_err(|e| GenError(e.to_string()))?;
            filled += set(items, rec, "KAB", &hex::encode_upper(&v)) as usize;
        }
    }
    Ok(GenOutcome::Generated(filled))
}

/// PGT: 도메인 파라미터 (P,Q,G)와 증거값(Seed,J,Count,h)을 생성한다.
/// KCDSA 와 동일한 TTAK.KO-12.0001 PQG 절차를 사용한다.
fn pgt(items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let p_bits = header_int(items, "|P|").ok_or_else(|| GenError("|P| 미발견".into()))?;
    let q_bits = header_int(items, "|Q|").ok_or_else(|| GenError("|Q| 미발견".into()))?;
    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        // Seed=? 가 있는 레코드만 생성 대상.
        if get(items, rec, "Seed").map(|v| v.contains('?')) != Some(true) {
            continue;
        }
        let mut key = KcdsaKey::new().map_err(|e| GenError(e.to_string()))?;
        let ev = key
            .generate_parameters(p_bits, q_bits)
            .map_err(|e| GenError(e.to_string()))?;
        let (p, q, g) = key.params().map_err(|e| GenError(e.to_string()))?;
        filled += set(items, rec, "Seed", &hex::encode_upper(&ev.seed)) as usize;
        filled += set(items, rec, "J", &hex::encode_upper(&ev.j)) as usize;
        // Count 는 이 스위트의 수치 필드 관례(|P|, RSAES e 등)에 따라 10진수.
        filled += set(items, rec, "Count", &ev.count.to_string()) as usize;
        filled += set(items, rec, "h", &hex::encode_upper(&ev.h)) as usize;
        filled += set(items, rec, "P", &hex::encode_upper(&p)) as usize;
        filled += set(items, rec, "Q", &hex::encode_upper(&q)) as usize;
        filled += set(items, rec, "G", &hex::encode_upper(&g)) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}

/// PVT: 주어진 도메인 파라미터 (P, Q, G)를 검증한다.
/// - IsPrime(P)/IsPrime(Q): Miller-Rabin 소수 판정 → PRIME / COMPOSITE
/// - IsValid(G): 2 ≤ G ≤ P-1 이고 G^Q mod P = 1 → SUCCESS / FAILED
fn pvt(items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let recs = records(items);
    let mut ctx = BigNumContext::new().map_err(|e| GenError(e.to_string()))?;
    let one = BigNum::from_slice(&[1]).map_err(|e| GenError(e.to_string()))?;
    let mut filled = 0;
    for rec in &recs {
        let p = match get(items, rec, "P") {
            Some(v) => bn(v)?,
            None => continue,
        };
        let q = bn(get(items, rec, "Q").unwrap_or("0"))?;
        let g = bn(get(items, rec, "G").unwrap_or("0"))?;

        // 소수 판정(64라운드 Miller-Rabin).
        let p_prime = p
            .is_prime(64, &mut ctx)
            .map_err(|e| GenError(e.to_string()))?;
        let q_prime = q
            .is_prime(64, &mut ctx)
            .map_err(|e| GenError(e.to_string()))?;
        filled += set(
            items,
            rec,
            "IsPrime(P)",
            if p_prime { "PRIME" } else { "COMPOSITE" },
        ) as usize;
        filled += set(
            items,
            rec,
            "IsPrime(Q)",
            if q_prime { "PRIME" } else { "COMPOSITE" },
        ) as usize;

        // 생성원 판정: 2 ≤ G ≤ P-1 이고 G^Q mod P = 1.
        let mut p_minus_1 = BigNum::new().map_err(|e| GenError(e.to_string()))?;
        p_minus_1
            .checked_sub(&p, &one)
            .map_err(|e| GenError(e.to_string()))?;
        let in_range = g.ucmp(&one) == Ordering::Greater && g.ucmp(&p_minus_1) != Ordering::Greater;
        let valid = if in_range {
            let mut t = BigNum::new().map_err(|e| GenError(e.to_string()))?;
            t.mod_exp(&g, &q, &p, &mut ctx)
                .map_err(|e| GenError(e.to_string()))?;
            t.ucmp(&one) == Ordering::Equal
        } else {
            false
        };
        filled += set(
            items,
            rec,
            "IsValid(G)",
            if valid { "SUCCESS" } else { "FAILED" },
        ) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}
