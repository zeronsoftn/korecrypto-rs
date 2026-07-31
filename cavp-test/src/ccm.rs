//! CCM CAVP 생성기 (GE=암호화, DV=복호검증). SP 800-38C.
//!
//! 라이브러리의 CCM AEAD 는 논스/태그 길이가 고정이라, 검증 벡터(가변 논스
//! 7~13B, 가변 태그)를 다루기 위해 CCM(CTR + CBC-MAC)을 블록암호 ECB 위에서
//! 직접 구성한다(128비트 블록: AES/ARIA/LEA/SEED). HIGHT(64비트)는 제외.
//! - GE: C = 암호문 || 태그(Tlen/8 바이트).
//! - DV: 태그 검증 성공 시 P=평문, 실패 시 줄 전체를 "INVALID" 로.

use crate::parser::{get, records, set, set_raw, Item};
use crate::{GenError, GenOutcome};
use korecrypto::symm::{Cipher, Crypter, Mode};

/// 알고리즘명 → ECB Cipher(단일 블록 암호화용).
fn lookup(algo: &str) -> Option<Cipher> {
    Some(match algo {
        "AES-128" => Cipher::aes_128_ecb(),
        "AES-192" => Cipher::aes_192_ecb(),
        "AES-256" => Cipher::aes_256_ecb(),
        "ARIA-128" => Cipher::aria_128_ecb(),
        "ARIA-192" => Cipher::aria_192_ecb(),
        "ARIA-256" => Cipher::aria_256_ecb(),
        "SEED-128" => Cipher::seed_ecb(),
        "LEA-128" => Cipher::lea_128_ecb(),
        "LEA-192" => Cipher::lea_192_ecb(),
        "LEA-256" => Cipher::lea_256_ecb(),
        _ => return None,
    })
}

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s.trim()).map_err(|e| GenError(format!("hex: {e}")))
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// 한 블록(16바이트) ECB 암호화.
fn enc(cipher: Cipher, key: &[u8], blk: &[u8]) -> Vec<u8> {
    let mut c = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    c.pad(false);
    let mut out = vec![0u8; blk.len() + cipher.block_size()];
    let n = c.update(blk, &mut out).unwrap();
    let m = c.finalize(&mut out[n..]).unwrap();
    out.truncate(n + m);
    out
}

/// AAD 길이 인코딩(SP 800-38C A.2.2).
fn encode_aad_len(a: usize) -> Vec<u8> {
    if a < 0xFF00 {
        (a as u16).to_be_bytes().to_vec()
    } else if a as u64 <= 0xFFFF_FFFF {
        let mut v = vec![0xFF, 0xFE];
        v.extend_from_slice(&(a as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![0xFF, 0xFF];
        v.extend_from_slice(&(a as u64).to_be_bytes());
        v
    }
}

/// 카운터 블록 A_i (플래그(q-1) || N || i[q바이트]).
fn ctr_block(q: usize, n: &[u8], i: u64) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[0] = (q - 1) as u8;
    b[1..1 + n.len()].copy_from_slice(n);
    let ib = i.to_be_bytes(); // 8바이트 빅엔디안
    b[16 - q..16].copy_from_slice(&ib[8 - q..8]);
    b
}

/// CCM CBC-MAC 로 태그 이전 블록 T(16바이트)를 계산한다.
fn cbc_mac(cipher: Cipher, key: &[u8], n: &[u8], a: &[u8], p: &[u8], t: usize) -> Vec<u8> {
    let q = 15 - n.len();
    let adata = !a.is_empty();
    // B0.
    let mut b0 = vec![0u8; 16];
    b0[0] = (if adata { 0x40 } else { 0 }) | ((((t - 2) / 2) as u8) << 3) | ((q - 1) as u8);
    b0[1..1 + n.len()].copy_from_slice(n);
    let plen = (p.len() as u64).to_be_bytes();
    b0[16 - q..16].copy_from_slice(&plen[8 - q..8]);

    // AAD(길이인코딩+A, 16 패딩) || P(16 패딩).
    let mut data = Vec::new();
    if adata {
        data.extend(encode_aad_len(a.len()));
        data.extend_from_slice(a);
        while data.len() % 16 != 0 {
            data.push(0);
        }
    }
    data.extend_from_slice(p);
    while data.len() % 16 != 0 {
        data.push(0);
    }

    let mut y = enc(cipher, key, &b0);
    for blk in data.chunks(16) {
        y = enc(cipher, key, &xor(&y, blk));
    }
    y
}

/// CTR 로 payload 를 암/복호(대칭). data 길이만큼 키스트림 XOR.
fn ctr_crypt(cipher: Cipher, key: &[u8], n: &[u8], data: &[u8]) -> Vec<u8> {
    let q = 15 - n.len();
    let mut out = Vec::with_capacity(data.len());
    for (j, blk) in data.chunks(16).enumerate() {
        let s = enc(cipher, key, &ctr_block(q, n, (j + 1) as u64));
        out.extend_from_slice(&xor(blk, &s[..blk.len()]));
    }
    out
}

/// CCM 암호화: (ciphertext, tag).
fn ccm_encrypt(
    cipher: Cipher,
    key: &[u8],
    n: &[u8],
    a: &[u8],
    p: &[u8],
    t: usize,
) -> (Vec<u8>, Vec<u8>) {
    let q = 15 - n.len();
    let mac = cbc_mac(cipher, key, n, a, p, t);
    let s0 = enc(cipher, key, &ctr_block(q, n, 0));
    let tag = xor(&mac[..t], &s0[..t]);
    let ct = ctr_crypt(cipher, key, n, p);
    (ct, tag)
}

/// CCM 복호검증: Some(plaintext) 성공, None 실패.
fn ccm_decrypt(
    cipher: Cipher,
    key: &[u8],
    n: &[u8],
    a: &[u8],
    ct: &[u8],
    tag: &[u8],
    t: usize,
) -> Option<Vec<u8>> {
    let q = 15 - n.len();
    let p = ctr_crypt(cipher, key, n, ct);
    let mac = cbc_mac(cipher, key, n, a, &p, t);
    let s0 = enc(cipher, key, &ctr_block(q, n, 0));
    let expect = xor(&mac[..t], &s0[..t]);
    if expect == tag {
        Some(p)
    } else {
        None
    }
}

/// 파일명 "CCM_<ALGO>_<GE|DV>" → (ALGO, 유형).
fn parse_name(stem: &str) -> Option<(String, String)> {
    let rest = stem.strip_prefix("CCM_")?;
    let us = rest.rfind('_')?;
    Some((rest[..us].to_string(), rest[us + 1..].to_string()))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (algo, ttype) = match parse_name(stem) {
        Some(t) => t,
        None => return Ok(GenOutcome::Skipped("CCM 파일명 파싱 실패".into())),
    };
    let cipher = match lookup(&algo) {
        Some(c) => c,
        None => return Ok(GenOutcome::Skipped(format!("미지원 CCM 암호: {algo}"))),
    };

    let recs = records(items);
    let mut filled = 0usize;
    for rec in &recs {
        let key = match get(items, rec, "K") {
            Some(k) => hx(k)?,
            None => continue,
        };
        let n = hx(get(items, rec, "N").unwrap_or(""))?;
        let a = hx(get(items, rec, "A").unwrap_or(""))?;
        let tlen_bits: usize = match get(items, rec, "Tlen") {
            Some(t) => t
                .trim()
                .parse()
                .map_err(|e| GenError(format!("Tlen: {e}")))?,
            None => continue,
        };
        let t = tlen_bits / 8;

        match ttype.as_str() {
            "GE" => {
                if get(items, rec, "C").is_none() {
                    continue;
                }
                let p = hx(get(items, rec, "P").unwrap_or(""))?;
                let (ct, tag) = ccm_encrypt(cipher, &key, &n, &a, &p, t);
                let mut c = ct;
                c.extend_from_slice(&tag);
                if set(items, rec, "C", &hex::encode_upper(&c)) {
                    filled += 1;
                }
            }
            "DV" => {
                if get(items, rec, "P").is_none() {
                    continue;
                }
                let c = hx(get(items, rec, "C").unwrap_or(""))?;
                if c.len() < t {
                    return Err(GenError("C 길이 < 태그".into()));
                }
                let (ct, tag) = c.split_at(c.len() - t);
                // 성공 시 "P = <평문>", 실패 시 줄 전체를 bare "INVALID" 로 치환
                // (검증시스템은 "P = INVALID" 가 아닌 "INVALID" 만 허용).
                match ccm_decrypt(cipher, &key, &n, &a, ct, tag, t) {
                    Some(p) => {
                        if set(items, rec, "P", &hex::encode_upper(&p)) {
                            filled += 1;
                        }
                    }
                    None => {
                        if set_raw(items, rec, "P", "INVALID") {
                            filled += 1;
                        }
                    }
                }
            }
            other => return Ok(GenOutcome::Skipped(format!("미지원 CCM 유형: {other}"))),
        }
    }
    Ok(GenOutcome::Generated(filled))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    // RFC 3610 Test Vector #1 로 CCM 암호화를 검증한다(태그 8바이트).
    #[test]
    fn ccm_rfc3610_vec1() {
        let key = Vec::from_hex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF").unwrap();
        let nonce = Vec::from_hex("00000003020100A0A1A2A3A4A5").unwrap();
        let aad = Vec::from_hex("0001020304050607").unwrap();
        let p = Vec::from_hex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E").unwrap();
        let (ct, tag) = ccm_encrypt(Cipher::aes_128_ecb(), &key, &nonce, &aad, &p, 8);
        let mut c = ct;
        c.extend_from_slice(&tag);
        assert_eq!(
            hex::encode_upper(&c),
            "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0"
        );
        // 복호 왕복.
        let (ct2, tag2) = c.split_at(c.len() - 8);
        let dec = ccm_decrypt(Cipher::aes_128_ecb(), &key, &nonce, &aad, ct2, tag2, 8);
        assert_eq!(dec.as_deref(), Some(p.as_slice()));
    }
}
