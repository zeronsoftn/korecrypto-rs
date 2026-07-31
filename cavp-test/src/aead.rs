//! GCM CAVP 생성기 (AE=암호화, AD=복호화).
//!
//! AES/ARIA/LEA/SEED GCM 을 지원한다. TagLen 은 헤더에서 읽는다.
//! (CCM/CMAC 은 후속.)

use crate::parser::{get, records_with_sections, set, set_raw, Item};
use crate::{GenError, GenOutcome};
use korecrypto::symm::{decrypt_aead, encrypt_aead, Cipher};

fn gcm_cipher(algo: &str) -> Option<Cipher> {
    Some(match algo {
        "AES-128" => Cipher::aes_128_gcm(),
        "AES-192" => Cipher::aes_192_gcm(),
        "AES-256" => Cipher::aes_256_gcm(),
        "ARIA-128" => Cipher::aria_128_gcm(),
        "ARIA-192" => Cipher::aria_192_gcm(),
        "ARIA-256" => Cipher::aria_256_gcm(),
        "LEA-128" => Cipher::lea_128_gcm(),
        "LEA-192" => Cipher::lea_192_gcm(),
        "LEA-256" => Cipher::lea_256_gcm(),
        "SEED-128" => Cipher::seed_gcm(),
        _ => return None,
    })
}

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}

/// "GCM_AES-128_AE" → ("AES-128","AE").
fn parse_name(stem: &str) -> Option<(String, String)> {
    let rest = stem.strip_prefix("GCM_")?;
    let us = rest.rfind('_')?;
    Some((rest[..us].to_string(), rest[us + 1..].to_string()))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (algo, dir) = match parse_name(stem) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped("GCM 파일명 파싱 실패".into())),
    };
    let cipher = match gcm_cipher(&algo) {
        Some(c) => c,
        None => return Ok(GenOutcome::Skipped(format!("미지원 GCM 암호: {algo}"))),
    };

    let recs = records_with_sections(items);
    let mut filled = 0;
    for (rec, sect) in &recs {
        // 태그 길이는 레코드가 속한 섹션의 [TagLen](비트)에서 가져온다.
        let tlen = sect
            .get("TagLen")
            .and_then(|v| v.parse::<usize>().ok())
            .map(|b| b / 8)
            .unwrap_or(16);
        let key = match get(items, rec, "Key") {
            Some(v) => hx(v)?,
            None => continue,
        };
        let iv = hx(get(items, rec, "IV").unwrap_or(""))?;
        let aad = hx(get(items, rec, "Adata").unwrap_or(""))?;

        match dir.as_str() {
            "AE" => {
                let pt = hx(get(items, rec, "PT").unwrap_or(""))?;
                let mut tag = vec![0u8; tlen];
                let ct = encrypt_aead(cipher, &key, Some(&iv), &aad, &pt, &mut tag)
                    .map_err(|e| GenError(e.to_string()))?;
                filled += set(items, rec, "C", &hex::encode_upper(&ct)) as usize;
                filled += set(items, rec, "T", &hex::encode_upper(&tag)) as usize;
            }
            "AD" => {
                let ct = hx(get(items, rec, "C").unwrap_or(""))?;
                let tag = hx(get(items, rec, "T").unwrap_or(""))?;
                // 실패 토큰은 템플릿("PT = ? or Invalid")의 "or" 뒤에서 가져온다.
                let fail_tok = get(items, rec, "PT")
                    .and_then(|v| v.split(" or ").nth(1))
                    .unwrap_or("Invalid")
                    .trim()
                    .to_string();
                match decrypt_aead(cipher, &key, Some(&iv), &aad, &ct, &tag) {
                    // 성공: PT = <평문 hex>
                    Ok(pt) => {
                        filled += set(items, rec, "PT", &hex::encode_upper(&pt)) as usize;
                    }
                    // 실패: 줄 전체를 "Invalid" 로 치환(앞의 "PT = " 없이).
                    Err(_) => {
                        filled += set_raw(items, rec, "PT", &fail_tok) as usize;
                    }
                }
            }
            other => return Ok(GenOutcome::Skipped(format!("미지원 방향: {other}"))),
        }
    }
    Ok(GenOutcome::Generated(filled))
}
