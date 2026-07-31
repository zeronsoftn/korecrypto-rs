//! CTR_DRBG CAVP 생성기 (SP 800-90A).
//!
//! 하부 블록암호 구성 가능(AES-128/192/256·ARIA·SEED·LEA·HIGHT), df/no-df,
//! PR/no-PR. CAVP 관례: instantiate 후 generate 2회 호출, 두 번째 출력을 답으로.
//! - no PR(+reseed): instantiate → reseed → generate(add) ×2
//! - use PR: instantiate → (reseed(EntropyInputPR, add) → generate()) ×2

use crate::parser::{get, get_all, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::drbg::{CtrDrbg, CtrDrbgCipher};

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}

/// 파일명에서 (cipher, keylen바이트) 추출. 예: "..._AES-128_KAT".
fn parse_cipher(stem: &str) -> Option<(CtrDrbgCipher, usize)> {
    let close = stem.rfind(')')?;
    let rest = stem[close + 1..].trim_start_matches('_');
    let name = rest.trim_end_matches("_KAT");
    let (cipher, bits) = if let Some(b) = name.strip_prefix("AES-") {
        (CtrDrbgCipher::Aes, b.parse().ok()?)
    } else if let Some(b) = name.strip_prefix("ARIA-") {
        (CtrDrbgCipher::Aria, b.parse().ok()?)
    } else if let Some(b) = name.strip_prefix("LEA-") {
        (CtrDrbgCipher::Lea, b.parse().ok()?)
    } else if name.starts_with("SEED") {
        (CtrDrbgCipher::Seed, 128usize)
    } else if name.starts_with("HIGHT") {
        (CtrDrbgCipher::Hight, 128usize)
    } else {
        return None;
    };
    Some((cipher, bits / 8))
}

fn header_int(items: &[Item], key: &str) -> Option<usize> {
    for it in items {
        if let Item::Raw(s) = it {
            if let Some(v) = s.strip_prefix(&format!("[{key} = ")) {
                return v.trim_end_matches(']').trim().parse().ok();
            }
        }
    }
    None
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (cipher, keylen) = match parse_cipher(stem) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped("CTR_DRBG 파일명 파싱 실패".into())),
    };
    let use_df = stem.contains("(use DF)");
    let ret_bits = header_int(items, "ReturnedBitsLen").unwrap_or(0);
    if ret_bits == 0 {
        return Ok(GenOutcome::Skipped("ReturnedBitsLen 미발견".into()));
    }
    let out_len = ret_bits / 8;

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        if get(items, rec, "EntropyInput").is_none() || get(items, rec, "ReturnedBits").is_none() {
            continue;
        }
        let entropy = hx(get(items, rec, "EntropyInput").unwrap())?;
        let nonce = hx(get(items, rec, "Nonce").unwrap_or(""))?;
        let perso = hx(get(items, rec, "PersonalizationString").unwrap_or(""))?;
        let adds: Vec<Vec<u8>> = get_all(items, rec, "AdditionalInput")
            .iter()
            .map(|s| hx(s))
            .collect::<Result<_, _>>()?;

        let mut d = CtrDrbg::new(cipher, keylen, use_df, &entropy, &nonce, &perso)
            .map_err(|e| GenError(e.to_string()))?;
        let mut last = vec![0u8; out_len];

        if let Some(rs) = get(items, rec, "EntropyInputReseed") {
            // no PR: instantiate → reseed → generate ×N
            let reseed_ent = hx(rs)?;
            let reseed_add = hx(get(items, rec, "AdditionalInputReseed").unwrap_or(""))?;
            d.reseed(&reseed_ent, &reseed_add)
                .map_err(|e| GenError(e.to_string()))?;
            for a in &adds {
                d.generate(&mut last, a)
                    .map_err(|e| GenError(e.to_string()))?;
            }
        } else if !get_all(items, rec, "EntropyInputPR").is_empty() {
            // use PR: (reseed(EntropyInputPR, add) → generate()) ×N
            let prs: Vec<Vec<u8>> = get_all(items, rec, "EntropyInputPR")
                .iter()
                .map(|s| hx(s))
                .collect::<Result<_, _>>()?;
            for (e, a) in prs.iter().zip(adds.iter()) {
                d.reseed(e, a).map_err(|e| GenError(e.to_string()))?;
                d.generate(&mut last, &[])
                    .map_err(|e| GenError(e.to_string()))?;
            }
        } else {
            for a in &adds {
                d.generate(&mut last, a)
                    .map_err(|e| GenError(e.to_string()))?;
            }
        }

        if set(items, rec, "ReturnedBits", &hex::encode_upper(&last)) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}
