//! DRBG CAVP 생성기 — Hash_DRBG / HMAC_DRBG (SP 800-90A).
//!
//! CAVP 관례: instantiate 후 generate 를 2회 호출하고 두 번째 출력을 답으로 쓴다.
//! - no PR(+reseed): instantiate → reseed → generate(add) ×2
//! - use PR: instantiate → (reseed(EntropyInputPR, add) → generate()) ×2
//!
//! CTR_DRBG 는 별도(미지원: BoringSSL CTR_DRBG 는 AES-256 고정·미노출).

use crate::parser::{get, get_all, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::drbg::{HashDrbg, HmacDrbg};
use korecrypto::hash::MessageDigest;

enum Kind {
    Hash,
    Hmac,
}

fn md_for(name: &str) -> Option<MessageDigest> {
    Some(match name {
        "SHA2-224" | "SHA-224" => MessageDigest::sha224(),
        "SHA2-256" | "SHA-256" => MessageDigest::sha256(),
        "SHA2-384" | "SHA-384" => MessageDigest::sha384(),
        "SHA2-512" | "SHA-512" => MessageDigest::sha512(),
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

/// 파일명에서 (Kind, 해시명, ReturnedBitsLen 은 헤더에서) 추출.
/// 예: "Hash_DRBG_(no PR)_LSH-256-224_KAT".
fn parse_name(stem: &str) -> Option<(Kind, String)> {
    let kind = if stem.starts_with("Hash_DRBG") {
        Kind::Hash
    } else if stem.starts_with("HMAC_DRBG") {
        Kind::Hmac
    } else {
        return None;
    };
    // 마지막 ')' 뒤 ~ "_KAT" 앞이 해시명.
    let close = stem.rfind(')')?;
    let rest = stem[close + 1..].trim_start_matches('_');
    let hashname = rest.trim_end_matches("_KAT").to_string();
    Some((kind, hashname))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    if stem.starts_with("CTR_DRBG") {
        return Ok(GenOutcome::Skipped(
            "CTR_DRBG 미지원(AES-256 고정·미노출)".into(),
        ));
    }
    let (kind, hashname) = match parse_name(stem) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped("DRBG 파일명 파싱 실패".into())),
    };
    let md = match md_for(&hashname) {
        Some(m) => m,
        None => return Ok(GenOutcome::Skipped(format!("미지원 DRBG 해시: {hashname}"))),
    };

    // ReturnedBitsLen 헤더(비트) → 출력 바이트.
    let mut ret_bits = 0usize;
    for it in items.iter() {
        if let Item::Raw(s) = it {
            if let Some(v) = s.strip_prefix("[ReturnedBitsLen = ") {
                ret_bits = v.trim_end_matches(']').trim().parse().unwrap_or(0);
            }
        }
    }
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

        let out = if let Some(rs) = get(items, rec, "EntropyInputReseed") {
            // no PR: instantiate → reseed → generate ×N(=adds.len())
            let reseed_ent = hx(rs)?;
            let reseed_add = hx(get(items, rec, "AdditionalInputReseed").unwrap_or(""))?;
            run(&kind, md, &entropy, &nonce, &perso, out_len, |d| {
                d.reseed(&reseed_ent, &reseed_add)?;
                let mut last = vec![0u8; out_len];
                for a in &adds {
                    d.generate(&mut last, a)?;
                }
                Ok(last)
            })?
        } else if !get_all(items, rec, "EntropyInputPR").is_empty() {
            // use PR: (reseed(EntropyInputPR, add) → generate()) ×N
            let prs: Vec<Vec<u8>> = get_all(items, rec, "EntropyInputPR")
                .iter()
                .map(|s| hx(s))
                .collect::<Result<_, _>>()?;
            run(&kind, md, &entropy, &nonce, &perso, out_len, |d| {
                let mut last = vec![0u8; out_len];
                for (e, a) in prs.iter().zip(adds.iter()) {
                    d.reseed(e, a)?;
                    d.generate(&mut last, &[])?;
                }
                Ok(last)
            })?
        } else {
            // reseed/PR 없음: instantiate → generate ×N
            run(&kind, md, &entropy, &nonce, &perso, out_len, |d| {
                let mut last = vec![0u8; out_len];
                for a in &adds {
                    d.generate(&mut last, a)?;
                }
                Ok(last)
            })?
        };

        if set(items, rec, "ReturnedBits", &hex::encode_upper(&out)) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}

/// Hash/HMAC DRBG 공통 실행 래퍼(트레잇 없이 분기).
trait Drbg {
    fn reseed(&mut self, e: &[u8], a: &[u8]) -> Result<(), GenError>;
    fn generate(&mut self, out: &mut [u8], a: &[u8]) -> Result<(), GenError>;
}
impl Drbg for HashDrbg {
    fn reseed(&mut self, e: &[u8], a: &[u8]) -> Result<(), GenError> {
        HashDrbg::reseed(self, e, a).map_err(|e| GenError(e.to_string()))
    }
    fn generate(&mut self, out: &mut [u8], a: &[u8]) -> Result<(), GenError> {
        HashDrbg::generate(self, out, a).map_err(|e| GenError(e.to_string()))
    }
}
impl Drbg for HmacDrbg {
    fn reseed(&mut self, e: &[u8], a: &[u8]) -> Result<(), GenError> {
        HmacDrbg::reseed(self, e, a).map_err(|e| GenError(e.to_string()))
    }
    fn generate(&mut self, out: &mut [u8], a: &[u8]) -> Result<(), GenError> {
        HmacDrbg::generate(self, out, a).map_err(|e| GenError(e.to_string()))
    }
}

fn run<F>(
    kind: &Kind,
    md: MessageDigest,
    entropy: &[u8],
    nonce: &[u8],
    perso: &[u8],
    _out_len: usize,
    body: F,
) -> Result<Vec<u8>, GenError>
where
    F: FnOnce(&mut dyn Drbg) -> Result<Vec<u8>, GenError>,
{
    match kind {
        Kind::Hash => {
            let mut d =
                HashDrbg::new(md, entropy, nonce, perso).map_err(|e| GenError(e.to_string()))?;
            body(&mut d)
        }
        Kind::Hmac => {
            let mut d =
                HmacDrbg::new(md, entropy, nonce, perso).map_err(|e| GenError(e.to_string()))?;
            body(&mut d)
        }
    }
}
