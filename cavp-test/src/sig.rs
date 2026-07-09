//! 전자서명 CAVP 생성기 — EC-KCDSA(P-224/P-256), KCDSA(검증 SVT).
//!
//! 시험유형: KPG(키쌍생성), PKV(공개키검증), SGT(서명생성), SVT(서명검증).
//! 이진체 곡선(B/K-233/283)·곡선≠해시 길이(P-224+SHA-256)·KCDSA 파라미터
//! 생성(KPG/SGT)은 현재 미지원으로 건너뛴다.

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::eckcdsa::EcKcdsaKey;
use korecrypto::hash::MessageDigest;
use korecrypto::kcdsa::KcdsaKey;
use korecrypto::nid::Nid;
use korecrypto::rand::rand_bytes;

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}

fn md_for(name: &str) -> Option<MessageDigest> {
    Some(match name {
        "SHA-224" | "SHA2-224" => MessageDigest::sha224(),
        "SHA-256" | "SHA2-256" => MessageDigest::sha256(),
        _ => return None,
    })
}

// ===================== EC-KCDSA =====================

/// "EC-KCDSA_(P-224)_SHA-224_SGT" → (curve, hash, type).
fn parse_eckcdsa(stem: &str) -> Option<(String, String, String)> {
    let open = stem.find('(')?;
    let close = stem.find(')')?;
    let curve = stem[open + 1..close].to_string();
    let rest = stem[close + 1..].trim_start_matches('_');
    let mut parts = rest.rsplitn(2, '_');
    let ttype = parts.next()?.to_string();
    let hash = parts.next()?.to_string();
    Some((curve, hash, ttype))
}

fn curve_nid(curve: &str) -> Option<(i32, usize)> {
    Some(match curve {
        "P-224" => (Nid::SECP224R1.as_raw(), 28),
        "P-256" => (Nid::X9_62_PRIME256V1.as_raw(), 32),
        _ => return None, // 이진체 곡선 미지원
    })
}

/// 무작위 개인키 d 를 설정한 EC-KCDSA 키를 만든다([1,n-1] 범위 재시도).
fn random_eckcdsa(nid: i32, coord: usize) -> Result<(EcKcdsaKey, Vec<u8>), GenError> {
    for _ in 0..32 {
        let mut d = vec![0u8; coord];
        rand_bytes(&mut d).map_err(|e| GenError(e.to_string()))?;
        let mut key = EcKcdsaKey::new(nid).map_err(|e| GenError(e.to_string()))?;
        if key.set_private(&d).is_ok() {
            return Ok((key, d));
        }
    }
    Err(GenError("개인키 생성 실패".into()))
}

fn eckcdsa(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (curve, hash, ttype) = match parse_eckcdsa(stem) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped("EC-KCDSA 파일명 파싱 실패".into())),
    };
    let (nid, coord) = match curve_nid(&curve) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped(format!("미지원 곡선(이진체): {curve}"))),
    };
    let md = md_for(&hash);
    // 서명/검증은 다이제스트 길이가 좌표 길이 이상이어야 한다(같으면 절단 없음,
    // 크면 라이브러리가 R 상위 바이트를 절단한다).
    let need_hash = matches!(ttype.as_str(), "SGT" | "SVT");
    if need_hash {
        match md {
            Some(m) if m.size() >= coord => {}
            _ => {
                return Ok(GenOutcome::Skipped(format!(
                    "해시 길이 < 좌표 길이 미지원: {curve}/{hash}"
                )))
            }
        }
    }
    let md = md.unwrap_or_else(MessageDigest::sha256);

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        match ttype.as_str() {
            "KPG" => {
                if get(items, rec, "d").is_none() {
                    continue;
                }
                let (key, d) = random_eckcdsa(nid, coord)?;
                let (qx, qy) = key.public_coords().map_err(|e| GenError(e.to_string()))?;
                filled += set(items, rec, "d", &hex::encode_upper(&d)) as usize;
                filled += set(items, rec, "Qx", &hex::encode_upper(&qx)) as usize;
                filled += set(items, rec, "Qy", &hex::encode_upper(&qy)) as usize;
            }
            "PKV" => {
                let qx = match get(items, rec, "Qx") {
                    Some(v) => hx(v)?,
                    None => continue,
                };
                let qy = hx(get(items, rec, "Qy").unwrap_or(""))?;
                let mut key = EcKcdsaKey::new(nid).map_err(|e| GenError(e.to_string()))?;
                let verdict = if key.set_public(&qx, &qy).is_ok() {
                    "P"
                } else {
                    "F"
                };
                filled += set(items, rec, "Result", verdict) as usize;
            }
            "SGT" => {
                let m = match get(items, rec, "M") {
                    Some(v) => hx(v)?,
                    None => continue,
                };
                let (key, _d) = random_eckcdsa(nid, coord)?;
                let (qx, qy) = key.public_coords().map_err(|e| GenError(e.to_string()))?;
                let sig = key
                    .sign(md, &m, None)
                    .map_err(|e| GenError(e.to_string()))?;
                let (r, s) = sig.split_at(coord);
                filled += set(items, rec, "Qx", &hex::encode_upper(&qx)) as usize;
                filled += set(items, rec, "Qy", &hex::encode_upper(&qy)) as usize;
                filled += set(items, rec, "R", &hex::encode_upper(r)) as usize;
                filled += set(items, rec, "S", &hex::encode_upper(s)) as usize;
            }
            "SVT" => {
                let m = match get(items, rec, "M") {
                    Some(v) => hx(v)?,
                    None => continue,
                };
                let qx = hx(get(items, rec, "Qx").unwrap_or(""))?;
                let qy = hx(get(items, rec, "Qy").unwrap_or(""))?;
                let mut sig = hx(get(items, rec, "R").unwrap_or(""))?;
                sig.extend(hx(get(items, rec, "S").unwrap_or(""))?);
                let mut key = EcKcdsaKey::new(nid).map_err(|e| GenError(e.to_string()))?;
                let verdict = if key.set_public(&qx, &qy).is_ok() && key.verify(md, &m, &sig) {
                    "P"
                } else {
                    "F"
                };
                filled += set(items, rec, "Result", verdict) as usize;
            }
            other => return Ok(GenOutcome::Skipped(format!("미지원 시험유형: {other}"))),
        }
    }
    Ok(GenOutcome::Generated(filled))
}

// ===================== KCDSA =====================

/// "KCDSA_(2048)(224)_SHA-224_SVT" → (|Q|bytes, hash, type).
fn parse_kcdsa(stem: &str) -> Option<(usize, String, String)> {
    // 두 번째 괄호가 |Q| 비트.
    let close1 = stem.find(')')?;
    let rest = &stem[close1 + 1..];
    let open2 = rest.find('(')?;
    let close2 = rest.find(')')?;
    let qbits: usize = rest[open2 + 1..close2].parse().ok()?;
    let tail = rest[close2 + 1..].trim_start_matches('_');
    let mut parts = tail.rsplitn(2, '_');
    let ttype = parts.next()?.to_string();
    let hash = parts.next()?.to_string();
    Some((qbits / 8, hash, ttype))
}

fn kcdsa(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (qbytes, hash, ttype) = match parse_kcdsa(stem) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped("KCDSA 파일명 파싱 실패".into())),
    };
    // 다이제스트 길이가 |Q| 이상이면 허용(크면 라이브러리가 R 을 절단).
    let md = match md_for(&hash) {
        Some(m) if m.size() >= qbytes => m,
        _ => {
            return Ok(GenOutcome::Skipped(format!(
                "해시 길이 < |Q| 미지원: {hash}/|Q|"
            )))
        }
    };
    let p_bits = parse_pbits(stem).unwrap_or(2048);
    let q_bits = qbytes * 8;
    match ttype.as_str() {
        "SGT" => return kcdsa_sgt(items, md, p_bits, q_bits),
        "KPG" => return kcdsa_kpg(items, md, p_bits, q_bits),
        "SVT" => {}
        other => return Ok(GenOutcome::Skipped(format!("KCDSA {other} 미지원"))),
    }

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        let p = match get(items, rec, "P") {
            Some(v) => hx(v)?,
            None => continue,
        };
        let q = hx(get(items, rec, "Q").unwrap_or(""))?;
        let g = hx(get(items, rec, "G").unwrap_or(""))?;
        let m = hx(get(items, rec, "M").unwrap_or(""))?;
        let y = hx(get(items, rec, "Y").unwrap_or(""))?;
        let mut sig = hx(get(items, rec, "R").unwrap_or(""))?;
        sig.extend(hx(get(items, rec, "S").unwrap_or(""))?);

        let mut key = KcdsaKey::new().map_err(|e| GenError(e.to_string()))?;
        let verdict = if key.set_params(&p, &q, &g).is_ok()
            && key.set_public(&y).is_ok()
            && key.verify(md, &m, &sig)
        {
            "P"
        } else {
            "F"
        };
        filled += set(items, rec, "Result", verdict) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}

/// "KCDSA_(2048)(224)_..." 에서 첫 괄호의 |P| 비트를 읽는다.
fn parse_pbits(stem: &str) -> Option<usize> {
    let open = stem.find('(')?;
    let close = stem.find(')')?;
    stem[open + 1..close].parse().ok()
}

/// SGT(서명생성): 도메인 파라미터를 1회 생성(파일 내 공유)하고, 레코드마다
/// 키쌍을 새로 생성하여 메시지 M 에 서명한다. 검증기는 각 서명을 Y 로 검증한다.
fn kcdsa_sgt(
    items: &mut [Item],
    md: MessageDigest,
    p_bits: usize,
    q_bits: usize,
) -> Result<GenOutcome, GenError> {
    let mut key = KcdsaKey::new().map_err(|e| GenError(e.to_string()))?;
    key.generate_parameters(p_bits, q_bits)
        .map_err(|e| GenError(e.to_string()))?;
    let (p, q, g) = key.params().map_err(|e| GenError(e.to_string()))?;
    let coord = q_bits / 8;

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        let m = match get(items, rec, "M") {
            Some(v) => hx(v)?,
            None => continue,
        };
        // 레코드마다 새 키쌍.
        key.generate().map_err(|e| GenError(e.to_string()))?;
        let x = key.private_key().map_err(|e| GenError(e.to_string()))?;
        let y = key.public_key().map_err(|e| GenError(e.to_string()))?;
        let sig = key
            .sign(md, &m, None)
            .map_err(|e| GenError(e.to_string()))?;
        let (r, s) = sig.split_at(coord);
        filled += set(items, rec, "P", &hex::encode_upper(&p)) as usize;
        filled += set(items, rec, "Q", &hex::encode_upper(&q)) as usize;
        filled += set(items, rec, "G", &hex::encode_upper(&g)) as usize;
        filled += set(items, rec, "X", &hex::encode_upper(&x)) as usize;
        filled += set(items, rec, "Y", &hex::encode_upper(&y)) as usize;
        filled += set(items, rec, "R", &hex::encode_upper(r)) as usize;
        filled += set(items, rec, "S", &hex::encode_upper(s)) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}

/// PPGF(TTAK.KO-12.0001 일방향 함수): digest=Hash(src‖Count(1B)) 를 출력
/// 버퍼의 끝(LSB)부터 앞으로 채우고 최상위 바이트를 out_bits 로 마스크한다.
fn ppgf(md: MessageDigest, src: &[u8], out_bits: usize) -> Result<Vec<u8>, GenError> {
    use korecrypto::hash::hash;
    let total = out_bits.div_ceil(8);
    let mut out = vec![0u8; total];
    let mut i = total;
    let mut count: u8 = 0;
    loop {
        let mut buf = src.to_vec();
        buf.push(count);
        count = count.wrapping_add(1);
        let dg = hash(md, &buf).map_err(|e| GenError(e.to_string()))?;
        let dl = dg.len();
        if i >= dl {
            i -= dl;
            out[i..i + dl].copy_from_slice(&dg);
            if i == 0 {
                break;
            }
        } else {
            out[..i].copy_from_slice(&dg[dl - i..]);
            break;
        }
    }
    let r = out_bits & 7;
    if r != 0 {
        out[0] &= (1u8 << r) - 1;
    }
    Ok(out)
}

/// KPG(키쌍생성): 레코드마다 도메인 파라미터(파일 해시로 PPGF)와 키쌍을
/// 생성한다. X 는 TTAK.KO-12.0001/R4:2016 §7.1 첫 번째 알고리즘(b=β=|Q|)으로
/// XKEY/OUPRI 에서 유도한다:
///   XSEED = PPGF(OUPRI, β), XVAL = (XKEY + XSEED) mod 2^β,
///   X = PPGF(XVAL, β) mod Q
/// Count 는 이 스위트의 수치 필드 관례(RSAES e, |P| 등)에 따라 10진수로 출력.
fn kcdsa_kpg(
    items: &mut [Item],
    md: MessageDigest,
    p_bits: usize,
    q_bits: usize,
) -> Result<GenOutcome, GenError> {
    use korecrypto::bn::BigNum;
    let recs = records(items);
    let coord = q_bits / 8;
    let mut filled = 0;
    for rec in &recs {
        // X=? 가 있는 레코드만 대상.
        if get(items, rec, "X").map(|v| v.contains('?')) != Some(true) {
            continue;
        }
        let mut key = KcdsaKey::new().map_err(|e| GenError(e.to_string()))?;
        let ev = key
            .generate_parameters_md(p_bits, q_bits, md)
            .map_err(|e| GenError(e.to_string()))?;
        let (p, q, g) = key.params().map_err(|e| GenError(e.to_string()))?;
        let q_bn = BigNum::from_slice(&q).map_err(|e| GenError(e.to_string()))?;

        // §7.1: XKEY 랜덤 β비트, OUPRI(사용자 난수) 32바이트(엔트로피 ≥ β).
        let (x, xkey, oupri) = loop {
            let mut xkey = vec![0u8; coord];
            let mut oupri = vec![0u8; 32];
            rand_bytes(&mut xkey).map_err(|e| GenError(e.to_string()))?;
            rand_bytes(&mut oupri).map_err(|e| GenError(e.to_string()))?;
            // XSEED = PPGF(OUPRI, β); XVAL = (XKEY + XSEED) mod 2^β.
            let xseed = ppgf(md, &oupri, q_bits)?;
            let xkey_bn = BigNum::from_slice(&xkey).map_err(|e| GenError(e.to_string()))?;
            let xseed_bn = BigNum::from_slice(&xseed).map_err(|e| GenError(e.to_string()))?;
            let mut sum = BigNum::new().map_err(|e| GenError(e.to_string()))?;
            sum.checked_add(&xkey_bn, &xseed_bn)
                .map_err(|e| GenError(e.to_string()))?;
            let sum_full = sum
                .to_vec_padded(coord + 1)
                .map_err(|e| GenError(e.to_string()))?;
            let xval = &sum_full[1..]; // mod 2^β = 하위 β/8 바이트
                                       // X = PPGF(XVAL, β) mod Q (2^β < 2Q 이므로 최대 1회 감산).
            let t2 = ppgf(md, xval, q_bits)?;
            let mut x_bn = BigNum::from_slice(&t2).map_err(|e| GenError(e.to_string()))?;
            if x_bn.ucmp(&q_bn) != std::cmp::Ordering::Less {
                let t2_bn = BigNum::from_slice(&t2).map_err(|e| GenError(e.to_string()))?;
                x_bn = BigNum::new().map_err(|e| GenError(e.to_string()))?;
                x_bn.checked_sub(&t2_bn, &q_bn)
                    .map_err(|e| GenError(e.to_string()))?;
            }
            let x = x_bn
                .to_vec_padded(coord)
                .map_err(|e| GenError(e.to_string()))?;
            // X=0 이면(사실상 불가능) 다시 뽑는다.
            if x.iter().any(|&b| b != 0) {
                break (x, xkey, oupri);
            }
        };
        // set_private 이 Y = G^{X^{-1} mod Q} mod P 를 계산한다.
        key.set_private(&x).map_err(|e| GenError(e.to_string()))?;
        let y = key.public_key().map_err(|e| GenError(e.to_string()))?;

        filled += set(items, rec, "P", &hex::encode_upper(&p)) as usize;
        filled += set(items, rec, "Q", &hex::encode_upper(&q)) as usize;
        filled += set(items, rec, "G", &hex::encode_upper(&g)) as usize;
        filled += set(items, rec, "X", &hex::encode_upper(&x)) as usize;
        filled += set(items, rec, "Y", &hex::encode_upper(&y)) as usize;
        filled += set(items, rec, "Seed", &hex::encode_upper(&ev.seed)) as usize;
        filled += set(items, rec, "Count", &ev.count.to_string()) as usize;
        filled += set(items, rec, "XKEY", &hex::encode_upper(&xkey)) as usize;
        filled += set(items, rec, "OUPRI", &hex::encode_upper(&oupri)) as usize;
        filled += set(items, rec, "h", &hex::encode_upper(&ev.h)) as usize;
        filled += set(items, rec, "J", &hex::encode_upper(&ev.j)) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}

// ===================== dispatch =====================

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    if stem.starts_with("EC-KCDSA") {
        eckcdsa(stem, items)
    } else if stem.starts_with("KCDSA") {
        kcdsa(stem, items)
    } else {
        Ok(GenOutcome::Skipped("서명 패밀리 아님".into()))
    }
}
